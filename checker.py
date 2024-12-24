import concurrent.futures
import re
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests
import urllib3
from bs4 import BeautifulSoup

# Unicode symbols
SUCCESS_SYMBOL = "✓"
FAIL_SYMBOL = "✗"
INSECURE_SYMBOL = "⚠"

# Silence insecure request warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def is_valid_url(url):
    """Validate URL format and structure."""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False


def clean_url(url):
    """Clean and normalize URL."""
    try:
        # Remove any trailing slashes and normalize
        url = url.strip("/")
        parsed = urlparse(url)
        return urljoin(parsed.scheme + "://" + parsed.netloc, parsed.path)
    except Exception:
        return url


def find_markdown_files(root_dir):
    """Recursively find all markdown files in the repository."""
    return list(Path(root_dir).rglob("*.md"))


def extract_links_with_lines(markdown_file):
    """Extract links and their line numbers from markdown file."""
    links = []
    with open(markdown_file, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            # Match markdown links [text](url)
            matches = re.finditer(r"\[([^\]]+)\]\(([^)]+)\)", line)
            for match in matches:
                # Skip relative links and anchors
                url = match.group(2)
                if not url.startswith(("http://", "https://")):
                    continue

                links.append(
                    {
                        "line_num": line_num,
                        "line": line.rstrip(),
                        "url": url,
                        "start": match.start(),
                        "end": match.end(),
                    }
                )
    return links


def check_link(url):
    """
    Check if link is accessible with improved error handling.
    Returns tuple: (is_accessible, is_secure, error_message)
    """
    if not is_valid_url(url):
        return False, True, f"Invalid URL format: {url}"

    cleaned_url = clean_url(url)

    try:
        # Custom headers to mimic a browser
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/91.0.4472.124 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/pdf,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
        }

        # First try with verification
        try:
            response = requests.get(
                cleaned_url,
                headers=headers,
                timeout=15,
                allow_redirects=True,
                verify=True,
            )
            return True, True, None
        except requests.exceptions.SSLError:
            response = requests.get(
                cleaned_url,
                headers=headers,
                timeout=15,
                allow_redirects=True,
                verify=False,
            )
            return True, False, "Insecure SSL"

        # Special handling for PDFs and binary content
        content_type = response.headers.get("Content-Type", "").lower()
        if any(t in content_type for t in ["pdf", "octet-stream", "binary"]):
            return response.status_code == 200, True, None

        # Only parse HTML content
        if "text/html" in content_type:
            try:
                soup = BeautifulSoup(
                    response.text, "html.parser", from_encoding=response.encoding
                )
                if soup.title and any(
                    err in soup.title.string.lower()
                    for err in ["404", "not found", "error", "page does not exist"]
                ):
                    return False, True, "404 or error page detected"
            except Exception as e:
                # If HTML parsing fails, just check status code
                pass

        return response.status_code == 200, True, None

    except requests.exceptions.Timeout:
        return False, True, "Timeout"
    except requests.exceptions.ConnectionError as e:
        if "Errno 111" in str(e):
            return False, True, "Connection refused"
        if "RemoteDisconnected" in str(e):
            return False, True, "Remote server disconnected"
        if "NameResolutionError" in str(e):
            return False, True, "DNS resolution failed"
        return False, True, "Connection error"
    except requests.exceptions.RequestException as e:
        return False, True, str(e)
    except Exception as e:
        return False, True, f"Unexpected error: {str(e)}"


def get_domain(url):
    """Extract domain from URL."""
    try:
        return urlparse(url).netloc
    except:
        return None


def process_markdown_file(file_path):
    """Process a single markdown file and return if changes were made."""
    links = extract_links_with_lines(file_path)
    if not links:
        return False

    # Group links by domain to avoid hammering the same server
    domain_grouped_links = {}
    for link in links:
        domain = get_domain(link["url"])
        if domain not in domain_grouped_links:
            domain_grouped_links[domain] = []
        domain_grouped_links[domain].append(link)

    # Check links with delays between domains
    url_status = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        for domain, domain_links in domain_grouped_links.items():
            futures = {
                executor.submit(check_link, link["url"]): link for link in domain_links
            }

            for future in concurrent.futures.as_completed(futures):
                link = futures[future]
                try:
                    is_accessible, is_secure, error = future.result()
                    url_status[link["url"]] = (is_accessible, is_secure)
                    if error:
                        print(f"[WARN] {link['url']}: {error}", file=sys.stderr)
                except Exception as e:
                    print(f"[ERR] {link['url']}: {str(e)}", file=sys.stderr)
                    url_status[link["url"]] = (False, True)

    with open(file_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    changes_made = False
    new_lines = []

    for i, line in enumerate(lines):
        line_num = i + 1
        current_links = [l for l in links if l["line_num"] == line_num]

        if not current_links:
            new_lines.append(line)
            continue

        # Remove existing symbols
        clean_line = re.sub(r"[✓✗⚠]\s*$", "", line.rstrip())

        # Add new symbols
        symbols = []
        for link in current_links:
            is_accessible, is_secure = url_status[link["url"]]
            if is_accessible and is_secure:
                symbols.append(SUCCESS_SYMBOL)
            elif is_accessible and not is_secure:
                symbols.append(INSECURE_SYMBOL)
            else:
                symbols.append(FAIL_SYMBOL)

        new_line = f"{clean_line} {' '.join(symbols)}\n"
        if new_line != line:
            changes_made = True

        new_lines.append(new_line)

    if changes_made:
        with open(file_path, "w", encoding="utf-8") as f:
            f.writelines(new_lines)

    return changes_made


def main():
    """Main function to process all markdown files."""
    repo_root = Path.cwd()
    markdown_files = find_markdown_files(repo_root)

    changes_made = False
    for md_file in markdown_files:
        if process_markdown_file(md_file):
            changes_made = True
            print(f"Updated links in: {md_file}")

    # Exit with status code 1 if no changes were made
    sys.exit(0 if changes_made else 1)


if __name__ == "__main__":
    main()

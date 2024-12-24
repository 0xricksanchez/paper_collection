import concurrent.futures
import random
import re
import sys
import time
from collections import defaultdict
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


class RateLimiter:
    """Simple rate limiter to track and limit requests per domain."""

    def __init__(self, min_delay=2):
        self.last_request = defaultdict(float)
        self.min_delay = min_delay

    def wait_if_needed(self, domain):
        """Wait if we need to respect rate limiting for this domain."""
        last_time = self.last_request[domain]
        now = time.time()

        if last_time > 0:
            elapsed = now - last_time
            if elapsed < self.min_delay:
                time.sleep(self.min_delay - elapsed + random.uniform(0.1, 0.5))

        self.last_request[domain] = time.time()


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


def check_link(url, rate_limiter):
    """Check if link is accessible with rate limiting."""
    if not is_valid_url(url):
        return False, True, f"Invalid URL format: {url}"

    cleaned_url = clean_url(url)
    domain = urlparse(cleaned_url).netloc
    rate_limiter.wait_if_needed(domain)

    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/91.0.4472.124 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/pdf,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
        }

        try:
            response = requests.get(
                cleaned_url,
                headers=headers,
                timeout=15,
                allow_redirects=True,
                verify=True,
                stream=True,  # Use streaming to avoid downloading large files
            )

            content_type = response.headers.get("Content-Type", "").lower()

            if ".pdf" in cleaned_url.lower() and "application/pdf" not in content_type:
                return False, True, "URL suggests PDF but received non-PDF content"

            if "text/html" in content_type or "application/xhtml" in content_type:
                content_sample = next(response.iter_content(16384)).decode(
                    errors="ignore"
                )
                soup = BeautifulSoup(content_sample, "html.parser")

                # Check title and body content for 404 indicators
                error_indicators = [
                    "404",
                    "not found",
                    "error",
                    "page does not exist",
                    "page not found",
                    "does not exist",
                    "no longer available",
                ]

                if soup.title and any(
                    ind in soup.title.string.lower() for ind in error_indicators
                ):
                    return False, True, "404 page detected (title)"

                body_text = soup.get_text().lower()
                if any(ind in body_text for ind in error_indicators):
                    return False, True, "404 page detected (content)"

                if len(content_sample) < 1000 and (
                    "404" in body_text or "not found" in body_text
                ):
                    return (
                        False,
                        True,
                        "Likely 404 page (short content with error message)",
                    )

            elif any(t in content_type for t in ["pdf", "octet-stream", "binary"]):
                content_length = response.headers.get("Content-Length")
                if (
                    content_length and int(content_length) < 100
                ):  # Suspiciously small for a PDF
                    return False, True, "File too small to be valid"

            return response.status_code == 200, True, None

        except requests.exceptions.SSLError:
            # Retry without SSL verification
            response = requests.get(
                cleaned_url,
                headers=headers,
                timeout=15,
                allow_redirects=True,
                verify=False,
                stream=True,
            )
            return True, False, "Insecure SSL"

    except requests.exceptions.Timeout:
        return False, True, "Timeout"
    except requests.exceptions.ConnectionError as e:
        if "Errno 111" in str(e):
            return False, True, "Connection refused"
        if "RemoteDisconnected" in str(e):
            return False, True, "Remote server disconnected"
        if "NameResolutionError" in str(e):
            return False, True, "DNS resolution failed"
        if "IncompleteRead" in str(e):
            return False, True, "Connection broken while reading response"
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

    # Group links by domain
    domain_grouped_links = {}
    for link in links:
        domain = get_domain(link["url"])
        if domain not in domain_grouped_links:
            domain_grouped_links[domain] = []
        domain_grouped_links[domain].append(link)

    # Process domains sequentially with rate limiting
    rate_limiter = RateLimiter(
        min_delay=3
    )  # At least 3 seconds between requests to same domain
    url_status = {}

    # Reduce concurrent workers to be more conservative
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        for domain, domain_links in domain_grouped_links.items():
            # Process each domain's links with rate limiting
            futures = {
                executor.submit(check_link, link["url"], rate_limiter): link
                for link in domain_links
            }

            # Add small delay between different domains
            time.sleep(1)

            for future in concurrent.futures.as_completed(futures):
                link = futures[future]
                try:
                    is_accessible, is_secure, error = future.result()
                    url_status[link["url"]] = (is_accessible, is_secure)
                    if error:
                        print(f"Warning for {link['url']}: {error}", file=sys.stderr)
                except Exception as e:
                    print(f"Error checking {link['url']}: {str(e)}", file=sys.stderr)
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
    """Main function to process all markdown files or a single URL."""
    if len(sys.argv) > 1:
        url = sys.argv[1]
        rate_limiter = RateLimiter(min_delay=3)
        is_accessible, is_secure, error = check_link(url, rate_limiter)

        if error:
            print(f"Warning for {url}: {error}", file=sys.stderr)

        if is_accessible and is_secure:
            print(f"{url}: {SUCCESS_SYMBOL}")
        elif is_accessible and not is_secure:
            print(f"{url}: {INSECURE_SYMBOL}")
        else:
            print(f"{url}: {FAIL_SYMBOL}")

        sys.exit(0 if is_accessible else 1)

    repo_root = Path.cwd()
    markdown_files = find_markdown_files(repo_root)

    changes_made = False
    for md_file in markdown_files:
        if process_markdown_file(md_file):
            changes_made = True
            print(f"Updated links in: {md_file}")

    sys.exit(0 if changes_made else 1)


if __name__ == "__main__":
    main()

import sys
import requests
import time
import os
import re
import json
import argparse
import logging
import base62
from tqdm import tqdm
import pickle
from typing import Tuple, Dict, Any, Optional, List, Set, Union

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')


def sanitize_filename(name: str) -> str:
    """
    Sanitizes a string to be safe for use as a filename and for YAML front matter.
    Removes characters that are invalid in filenames and converts spaces to underscores.
    """
    # Remove characters that are invalid in filenames: \ / * ? : " < > |
    name = re.sub(r'[\\/*?:"<>|]', "", name)
    # Replace spaces with underscores for a continuous filename format.
    name = name.replace(" ", "_")
    # Remove duplicate underscores and trim leading/trailing underscores/spaces.
    name = re.sub(r'_+', '_', name).strip('_ ')
    if not name:
        name = "unnamed_topic"
    return name


class DiscourseScraper:
    def __init__(self, base_url: str, auth_required: bool, username: str, password: str, passcode: Optional[str] = None,
                 rate_delay: float = 1.0, output_dir: str = "scraped", session_file: str = "session.pkl"):
        self.base_url = base_url.rstrip("/")
        self.auth_required = auth_required
        self.username = username
        self.password = password
        self.passcode = passcode
        self.rate_delay = rate_delay
        self.output_dir = output_dir
        self.session_file = session_file
        self.session = requests.Session()
        self._topic_json_cache: Dict[int, Tuple[Optional[str], Optional[Dict[str, Any]]]] = {}
        self._category_details_cache: Dict[int, Optional[Dict[str, Any]]] = {}

    def _request(self, method: str, url: str, **kwargs) -> requests.Response:
        """Internal helper for making rate-limited and error-handled requests."""
        while True:
            try:
                logging.debug(f"Requesting: {method} {url}")
                response = self.session.request(method, url, **kwargs)
                if response.status_code == 429:
                    retry_after = response.headers.get("retry-after")
                    try:
                        wait_time = float(retry_after)
                        logging.warning(f"Rate limit hit (429). Retrying after {wait_time:.2f} seconds.")
                    except (TypeError, ValueError):
                        wait_time = self.rate_delay * 5
                        logging.warning(f"Rate limit hit (429). Invalid/missing Retry-After header. Retrying after fallback: {wait_time:.2f} seconds.")
                    time.sleep(wait_time)
                    continue
                response.raise_for_status()
                time.sleep(self.rate_delay)
                return response
            except requests.exceptions.RequestException as e:
                logging.error(f"Request failed for {method} {url}: {e}. Retrying after delay...")
                time.sleep(self.rate_delay * 2)

    def save_session_to_disk(self):
        """Saves the current session cookies to a pickle file."""
        try:
            with open(self.session_file, "wb") as f:
                pickle.dump(self.session.cookies, f)
            logging.info(f"Session saved to disk: {self.session_file}")
        except Exception as e:
            logging.error(f"Error saving session to disk: {e}")

    def load_session_from_disk(self) -> bool:
        """Loads session cookies from a pickle file if it exists."""
        if os.path.exists(self.session_file):
            try:
                with open(self.session_file, "rb") as f:
                    self.session.cookies = pickle.load(f)
                logging.info(f"Loaded session from disk: {self.session_file}")
                return True
            except Exception as e:
                logging.error(f"Error loading session from disk: {e}")
        return False

    def login(self):
        """Logs into the Discourse forum, handling CSRF token and session persistence."""
        if self.load_session_from_disk():
            csrf_url = f"{self.base_url}/session/csrf.json"
            logging.info("Testing persisted session by fetching CSRF token.")
            try:
                headers = {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                    "X-Requested-With": "XMLHttpRequest",
                    "Accept": "application/json"
                }
                response = self.session.get(csrf_url, headers=headers, timeout=10)
                response.raise_for_status()
                csrf_data = response.json()
                if "csrf" in csrf_data:
                    logging.info("Persisted session appears valid. Skipping login.")
                    self.session.headers.update({
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                        "Referer": self.base_url + "/"
                    })
                    return
                else:
                    logging.warning("CSRF token not found in response during session test. Proceeding with login.")
            except (requests.exceptions.RequestException, json.JSONDecodeError) as e:
                logging.warning(f"Persisted session test failed ({e}). Proceeding with login.")

        csrf_url = f"{self.base_url}/session/csrf.json"
        logging.info(f"Fetching CSRF token from: {csrf_url}")
        try:
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                "X-Requested-With": "XMLHttpRequest",
                "Accept": "application/json"
            }
            r = self._request("GET", csrf_url, headers=headers, timeout=15)
            csrf_token = r.json().get("csrf")
            if not csrf_token:
                raise ValueError("CSRF token not found in response.")
            logging.info("CSRF token retrieved.")
        except (requests.exceptions.RequestException, json.JSONDecodeError, ValueError) as e:
            logging.critical(f"Fatal: Failed to get CSRF token: {e}")
            raise Exception(f"Failed to get CSRF token: {e}")

        payload = {
            "login": self.username,
            "password": self.password,
            "second_factor_method": "1",
            "timezone": time.tzname[0] if time.tzname else "UTC",
        }
        if self.passcode:
            payload["passcode"] = self.passcode
            payload["second_factor_method"] = "1"
        else:
            del payload["second_factor_method"]

        login_url = f"{self.base_url}/session"
        logging.info(f"Posting credentials to: {login_url}")
        try:
            login_resp = self._request("POST", login_url, data=payload,
                                       headers={
                                           "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                                           "X-CSRF-Token": csrf_token,
                                           "X-Requested-With": "XMLHttpRequest",
                                           "Accept": "application/json"
                                       }, timeout=30)
            content_type = login_resp.headers.get('Content-Type', '')
            login_data = {}
            success = False
            if 'application/json' in content_type:
                try:
                    login_data = login_resp.json()
                    if login_data.get('user') or login_data.get('success'):
                        success = True
                    elif 'error' in login_data:
                        error_msg = login_data['error']
                        logging.error(f"Login failed (JSON response): {error_msg}")
                        raise Exception(f"Login failed: {error_msg}")
                    else:
                        logging.warning("Login response JSON received, but no clear success/error indicator. Assuming failure.")
                        logging.debug(f"Login Response JSON: {login_data}")
                except json.JSONDecodeError:
                    logging.error("Login response indicated JSON but failed to parse.")
                    logging.debug(f"Login Response Text (Truncated): {login_resp.text[:500]}...")
                    raise Exception("Login failed: Invalid JSON response.")
            else:
                logging.warning(f"Login response was not JSON (Content-Type: {content_type}). Checking content for success indicators.")
                if "logout" in login_resp.text.lower() or self.username in login_resp.text:
                    logging.info("Non-JSON login response contains success indicators.")
                    success = True
                else:
                    logging.error("Login failed: Non-JSON response without clear success indicators.")
                    logging.debug(f"Login Response Text (Truncated): {login_resp.text[:500]}...")
                    raise Exception("Login failed: Unexpected response format.")

            if success:
                logging.info("Login successful.")
                self.session.headers.update({
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                    "Referer": self.base_url + "/",
                    "X-Requested-With": "XMLHttpRequest",
                    "Accept": "application/json"
                })
                logging.info("Session headers updated for API interaction.")
                self.save_session_to_disk()
            else:
                logging.error("Login sequence completed but success state unclear. Assuming failure.")
                raise Exception("Login failed: Unknown reason after response processing.")

        except requests.exceptions.RequestException as e:
            logging.critical(f"Fatal: Login POST request failed: {e}")
            if hasattr(e, 'response') and e.response is not None:
                logging.error(f"Login Response Status: {e.response.status_code}")
                logging.error(f"Login Response Body: {e.response.text[:500]}...")
            raise Exception(f"Login failed due to network/request error: {e}")
        except Exception as e:
            logging.critical(f"Fatal: An unexpected error occurred during login: {e}", exc_info=True)
            raise

    def _get_category_details(self, category_id: int) -> Optional[Dict[str, Any]]:
        """Fetches detailed information for a single category using the /show endpoint."""
        if category_id in self._category_details_cache:
            logging.debug(f"Using cached details for category ID: {category_id}")
            cached_data = self._category_details_cache[category_id]
            return json.loads(json.dumps(cached_data)) if cached_data else None

        url = f"{self.base_url}/c/{category_id}/show.json"
        logging.debug(f"Fetching details for category ID: {category_id} from {url}")
        try:
            response = self._request("GET", url)
            data = response.json()
            category_data = data.get("category")
            if category_data:
                category_data.setdefault("subcategories", [])
                category_data.setdefault("name", f"Unnamed Category {category_id}")
                category_data.setdefault("slug", sanitize_filename(category_data["name"]).lower())
                category_data.setdefault("id", category_id)
                self._category_details_cache[category_id] = category_data
                logging.debug(f"Successfully fetched details for category ID: {category_id} ('{category_data.get('name')}')")
                return json.loads(json.dumps(category_data))
            else:
                logging.warning(f"No 'category' key found in response for category ID: {category_id} at {url}")
                self._category_details_cache[category_id] = None
                return None
        except (requests.exceptions.RequestException, json.JSONDecodeError) as e:
            logging.error(f"Failed to retrieve or parse details for category ID {category_id}: {e}")
            if hasattr(e, 'response') and e.response is not None:
                if e.response.status_code == 404:
                    logging.warning(f"Category ID {category_id} not found (404).")
                elif e.response.status_code == 403:
                    logging.warning(f"Access denied (403) for category ID {category_id}.")
                else:
                    logging.error(f"HTTP Error {e.response.status_code} fetching category {category_id}.")
            self._category_details_cache[category_id] = None
            return None
        except Exception as e:
            logging.error(f"An unexpected error occurred fetching details for category {category_id}: {e}", exc_info=True)
            self._category_details_cache[category_id] = None
            return None

    def get_categories(self) -> Dict[int, Dict[str, Any]]:
        """
        Fetches all categories and their subcategories, building a full hierarchical structure.
        Returns:
            A dictionary where keys are top-level category IDs and values are fully detailed category dictionaries.
        """
        logging.info("Starting category hierarchy build...")
        self._category_details_cache.clear()
        top_level_url = f"{self.base_url}/categories.json"
        logging.info(f"Fetching top-level categories from: {top_level_url}")
        try:
            response = self._request("GET", top_level_url)
            top_level_data = response.json()
            initial_categories = top_level_data.get("category_list", {}).get("categories", [])
            if not initial_categories:
                logging.warning(f"No categories found in the initial response from {top_level_url}")
                return {}
        except (requests.exceptions.RequestException, json.JSONDecodeError) as e:
            logging.error(f"Failed to retrieve or parse top-level categories from {top_level_url}: {e}")
            return {}
        except Exception as e:
            logging.error(f"An unexpected error occurred fetching top-level categories: {e}", exc_info=True)
            return {}

        # Preserve the subcategory IDs from the initial listing.
        initial_subcat_ids: Dict[int, List[int]] = {}
        for top_cat in initial_categories:
            top_cat_id = top_cat.get("id")
            if top_cat_id is not None:
                initial_subcat_ids[top_cat_id] = top_cat.get("subcategory_ids", [])

        all_fetched_details: Dict[int, Dict[str, Any]] = {}
        ids_to_process: Set[int] = set()
        processed_ids: Set[int] = set()

        for top_cat in initial_categories:
            top_cat_id = top_cat.get("id")
            if top_cat_id is None:
                logging.warning(f"Found a top-level category without an ID: {top_cat.get('name')}. Skipping.")
                continue
            ids_to_process.add(top_cat_id)
            sub_ids = top_cat.get("subcategory_ids", [])
            for sub_id in sub_ids:
                if isinstance(sub_id, int):
                    ids_to_process.add(sub_id)
                else:
                    logging.warning(
                        f"Invalid subcategory ID '{sub_id}' found for top-level category {top_cat_id}. Skipping.")

        logging.info(f"Identified {len(ids_to_process)} potential categories to fetch details for.")

        while ids_to_process:
            current_id = ids_to_process.pop()
            if current_id in processed_ids:
                continue
            details = self._get_category_details(current_id)
            processed_ids.add(current_id)
            if details:
                all_fetched_details[current_id] = details
                new_sub_ids = details.get("subcategory_ids", [])
                for new_sub_id in new_sub_ids:
                    if isinstance(new_sub_id, int) and new_sub_id not in processed_ids:
                        ids_to_process.add(new_sub_id)

        logging.info(
            f"Fetched details for {len(all_fetched_details)} categories out of {len(processed_ids)} attempted.")

        if not all_fetched_details:
            logging.error("Failed to fetch details for any category.")
            return {}

        # Merge the initial subcategory IDs into category details if missing.
        for cat_id, details in all_fetched_details.items():
            if not details.get("subcategory_ids") and cat_id in initial_subcat_ids:
                details["subcategory_ids"] = initial_subcat_ids[cat_id]

        # Attach subcategories based on the (possibly merged) "subcategory_ids"
        for cat_id, parent_details in all_fetched_details.items():
            parent_details.setdefault("subcategories", [])
            parent_details["subcategories"].clear()
            sub_ids = parent_details.get("subcategory_ids", [])
            for sub_id in sub_ids:
                child_details = all_fetched_details.get(sub_id)
                if child_details:
                    parent_details["subcategories"].append(child_details)

        final_hierarchy: Dict[int, Dict[str, Any]] = {}
        for cat_id, cat_details in all_fetched_details.items():
            if cat_details.get("parent_category_id") is None:
                final_hierarchy[cat_id] = cat_details

        logging.info(f"Finished category hierarchy build. Found {len(final_hierarchy)} top-level categories.")
        return final_hierarchy

    def get_topics_for_category(self, category_slug: str, category_id: int, page: int = 0, fetch_only_direct: bool = False) -> List[Dict[str, Any]]:
        """Fetches topics for a specific category page."""
        if fetch_only_direct:
            url = f"{self.base_url}/c/{category_slug}/{category_id}/none.json?page={page}"
        else:
            url = f"{self.base_url}/c/{category_slug}/{category_id}.json?page={page}"
        logging.debug(f"Fetching topics for category '{category_slug}' (ID: {category_id}, Page: {page}) from: {url}")
        try:
            r = self._request("GET", url)
            data = r.json()
            topic_list_data = data.get("topic_list", {})
            topics = topic_list_data.get("topics", []) if topic_list_data else []
            logging.debug(f"Found {len(topics)} topics on page {page} for category {category_id}.")
            return topics
        except (requests.exceptions.RequestException, json.JSONDecodeError) as e:
            logging.error(f"Failed to retrieve topics for category {category_id} on page {page}: {e}")
            if hasattr(e, 'response') and e.response is not None:
                if e.response.status_code == 404:
                    logging.warning(f"Category {category_id} (slug: {category_slug}) endpoint not found (404).")
                elif e.response.status_code == 403:
                    logging.warning(f"Access denied (403) fetching topics for category {category_id}.")
            return []

    def get_topic_raw_markdown(self, topic_id: int) -> Optional[str]:
        """Fetches the raw markdown content of a single topic."""
        url = f"{self.base_url}/raw/{topic_id}"
        logging.debug(f"Fetching raw markdown for topic {topic_id} from: {url}")
        try:
            r = self._request("GET", url)
            if 'text/plain' in r.headers.get('Content-Type', '').lower():
                return r.text
            else:
                logging.warning(f"Expected text/plain but got '{r.headers.get('Content-Type')}' for raw topic {topic_id}. Content (truncated): {r.text[:200]}...")
                return None
        except requests.exceptions.RequestException as e:
            logging.error(f"Failed to retrieve raw markdown for topic {topic_id}: {e}")
            if hasattr(e, 'response') and e.response is not None:
                if e.response.status_code == 404:
                    logging.warning(f"Topic {topic_id} raw endpoint not found (404).")
                elif e.response.status_code == 403:
                    logging.warning(f"Access denied (403) for raw topic {topic_id}.")
            return None

    def get_topic_json(self, topic_id: int) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
        """Fetches the JSON data for a single topic, using a cache."""
        if topic_id in self._topic_json_cache:
            logging.debug(f"Using cached JSON for topic {topic_id}")
            return self._topic_json_cache[topic_id]

        url = f"{self.base_url}/t/{topic_id}.json"
        logging.debug(f"Fetching JSON for topic {topic_id} from: {url}")
        raw_text: Optional[str] = None
        parsed_dict: Optional[Dict[str, Any]] = None
        try:
            r = self._request("GET", url)
            raw_text = r.text
            if 'application/json' in r.headers.get('Content-Type', '').lower():
                try:
                    parsed_dict = r.json()
                except json.JSONDecodeError as json_e:
                    logging.error(f"Failed to decode JSON for topic {topic_id}: {json_e}. Raw text (truncated): {raw_text[:200]}...")
            else:
                logging.warning(f"Expected application/json but got '{r.headers.get('Content-Type')}' for topic JSON {topic_id}. Content (truncated): {raw_text[:200]}...")
        except requests.exceptions.RequestException as e:
            logging.error(f"Failed to retrieve JSON data for topic {topic_id}: {e}")
            if hasattr(e, 'response') and e.response is not None:
                raw_text = e.response.text
                if e.response.status_code == 404:
                    logging.warning(f"Topic JSON {topic_id} not found (404).")
                elif e.response.status_code == 403:
                    logging.warning(f"Access denied (403) for topic JSON {topic_id}.")
        self._topic_json_cache[topic_id] = (raw_text, parsed_dict)
        return raw_text, parsed_dict

    def _extract_metadata_from_json(self, topic_json_dict: Optional[Dict[str, Any]], topic_id: int) -> Dict[str, Any]:
        """Extracts relevant metadata fields from the parsed topic JSON dictionary."""
        metadata = {
            "topic_id": topic_id,
            "topic_title": None,
            "topic_url": None,
            "created_at": None,
            "last_posted_at": None,
            "first_post_updated_at": None,
            "is_admin_post": False,
            "created_by_username": None,
            "tags": [],
        }
        if not topic_json_dict:
            logging.warning(f"Cannot extract metadata for topic {topic_id}, JSON data is missing.")
            return metadata

        try:
            metadata["topic_title"] = topic_json_dict.get("title")
            metadata["created_at"] = topic_json_dict.get("created_at")
            metadata["last_posted_at"] = topic_json_dict.get("last_posted_at")
            metadata["tags"] = topic_json_dict.get("tags", [])
            creator_details = topic_json_dict.get("details", {}).get("created_by", {})
            metadata["created_by_username"] = creator_details.get("username")
            creator_is_admin = creator_details.get("admin", False)
            creator_is_moderator = creator_details.get("moderator", False)
            post_stream = topic_json_dict.get("post_stream", {})
            posts = post_stream.get("posts", [])
            if posts:
                first_post = posts[0]
                metadata["first_post_updated_at"] = first_post.get("updated_at")
                first_post_admin = first_post.get("admin", False)
                first_post_moderator = first_post.get("moderator", False)
                metadata["is_admin_post"] = bool(first_post_admin or first_post_moderator or creator_is_admin or creator_is_moderator)
                topic_slug = topic_json_dict.get("slug") or first_post.get("topic_slug")
                if topic_slug:
                    metadata["topic_url"] = f"{self.base_url}/t/{topic_slug}/{topic_id}"
                else:
                    metadata["topic_url"] = f"{self.base_url}/t/{topic_id}"
                    logging.warning(f"Could not find 'slug' or 'topic_slug' in JSON for topic {topic_id}. Using fallback URL.")
            else:
                logging.warning(f"No posts found in 'post_stream' for topic {topic_id}. Metadata might be incomplete.")
                topic_slug = topic_json_dict.get("slug")
                metadata["topic_url"] = f"{self.base_url}/t/{topic_slug}/{topic_id}" if topic_slug else f"{self.base_url}/t/{topic_id}"
                metadata["is_admin_post"] = bool(creator_is_admin or creator_is_moderator)
        except Exception as e:
            logging.error(f"Error extracting metadata for topic {topic_id}: {e}", exc_info=True)

        return metadata

    def get_upload_hex_id(self, short_url_or_filename: str) -> Optional[str]:
        """Decodes the base62 part of a Discourse upload URL to its hex ID."""
        short = short_url_or_filename
        if short.startswith("upload://"):
            short = short[len("upload://"):]
        base_part = os.path.splitext(short)[0]
        if not re.match(r'^[0-9A-Za-z]+$', base_part):
            logging.debug(f"String '{base_part}' does not look like a valid base62 ID.")
            return None
        image_id = base_part
        try:
            decoded_int = base62.decode(image_id, charset=base62.CHARSET_INVERTED)
            hex_id = hex(decoded_int)[2:].zfill(40)
            return hex_id
        except Exception as e:
            logging.warning(f"Failed to decode base62 ID '{image_id}': {e}")
            return None

    def convert_markdown_images(self, markdown: str, topic_id: int) -> str:
        """Attempts to convert relative 'upload://' image URLs in markdown to absolute URLs."""
        topic_json_text, _ = self.get_topic_json(topic_id)
        if topic_json_text is None:
            logging.warning(f"Could not fetch JSON text for topic {topic_id}. Skipping image URL conversion.")
            return markdown

        markdown_link_pattern = r"""
            \(                 
            (?:\s*)            
            (?:upload://)?     
            ([0-9A-Za-z]+)     
            (?:\.[a-zA-Z0-9]+)? 
            (?:\s*)            
            \)                 
        """

        def replace_image_url(match):
            base62_id_part = match.group(1)
            original_markdown_ref = match.group(0)
            logging.debug(f"Found potential upload ref: '{base62_id_part}' in topic {topic_id}")
            hex_id = self.get_upload_hex_id(base62_id_part)
            if not hex_id:
                logging.debug(f"Could not get hex ID from '{base62_id_part}'. Keeping original.")
                return original_markdown_ref
            url_pattern = rf'[\'"](https?://[^\'"\s<>]*/{re.escape(hex_id)}[^\'"\s<>]*)[\'"]'
            found_match = re.search(url_pattern, topic_json_text, re.IGNORECASE)
            if found_match:
                full_url = found_match.group(1)
                full_url = full_url.replace("&amp;", "&")
                logging.debug(f"Successfully mapped hex ID {hex_id} to full URL: {full_url}")
                return f"({full_url})"
            else:
                logging.warning(f"Hex ID {hex_id} not found in topic {topic_id} JSON. Keeping original link.")
                return original_markdown_ref

        converted_markdown = re.sub(markdown_link_pattern, replace_image_url, markdown, flags=re.VERBOSE)
        return converted_markdown

    def get_topic_filepath(self, topic_title: str, topic_id: int, path_parts: List[str]) -> str:
        """Generates a safe file path for a topic within the output directory structure."""
        #safe_title = sanitize_filename(topic_title)
        filename = f"{topic_id}.md"
        safe_path_parts = [sanitize_filename(part) for part in path_parts if part]
        directory = os.path.join(self.output_dir, *safe_path_parts)
        try:
            os.makedirs(directory, exist_ok=True)
        except OSError as e:
            logging.error(f"Failed to create directory '{directory}': {e}. Saving to output root.")
            directory = self.output_dir
            os.makedirs(directory, exist_ok=True)
        return os.path.join(directory, filename)

    def save_markdown(self, topic_title: str, topic_id: int, markdown: str,
                      path_parts: List[str],
                      metadata: Optional[Dict[str, Any]] = None):
        """
        Saves the markdown text to a file, prepending metadata in a YAML front matter block.
        Uses json.dumps to safely output string and list values in the YAML front matter,
        ensuring that any problematic characters in topic titles (or other fields) are correctly escaped.
        """
        filepath = self.get_topic_filepath(topic_title, topic_id, path_parts)
        logging.debug(f"Preparing to save topic {topic_id} to: {filepath}")
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                if metadata:
                    f.write("---\n")
                    key_order = [
                        "topic_id", "topic_title", "topic_url",
                        "category_id", "category_name", "subcategory_id", "subcategory_name",
                        "tags",
                        "created_at", "last_posted_at", "first_post_updated_at",
                        "created_by_username", "is_admin_post"
                    ]
                    for key in key_order:
                        if key in metadata and metadata[key] is not None:
                            value = metadata[key]
                            # For list and string types, use json.dumps to properly escape special characters.
                            if isinstance(value, (list, str)):
                                f.write(f"{key}: {json.dumps(value)}\n")
                            else:
                                f.write(f"{key}: {value}\n")
                    f.write("---\n\n")
                f.write(markdown)
            logging.info(f"Saved topic {topic_id} ('{metadata.get('topic_title', topic_title)[:50]}...') to {filepath}")
        except IOError as e:
            logging.error(f"Error saving file {filepath}: {e}")
        except Exception as e:
            logging.error(f"An unexpected error occurred while saving {filepath}: {e}", exc_info=True)

    def scrape_topics_in_category(self,
                                  category_data: Dict[str, Any],
                                  current_path_parts: List[str]):
        """
        Scrapes all direct topics within a single category.
        """
        category_id = category_data.get("id")
        category_slug = category_data.get("slug")
        category_name = category_data.get("name", f"Unnamed_{category_id}")
        if not all([category_id, category_slug]):
            logging.error(f"Category data missing ID or Slug. Data: {category_data}. Skipping topic scrape.")
            return
        page = 0
        processed_count = 0
        skipped_count = 0
        error_count = 0
        fetch_only_direct = True
        log_cat_path = "/".join(current_path_parts)
        logging.info(f"Scraping direct topics for category: '{log_cat_path}' (ID: {category_id})")
        while True:
            topics = self.get_topics_for_category(category_slug, category_id, page,
                                                  fetch_only_direct=fetch_only_direct)
            if not topics:
                if page == 0:
                    logging.info(f"No direct topics found for category '{log_cat_path}' (ID: {category_id}).")
                else:
                    logging.debug(f"No more direct topics found for category {category_id} on page {page+1}.")
                break
            page_desc = f"Cat '{log_cat_path}' (Page {page+1})"
            for topic in tqdm(topics, desc=page_desc, unit="topic", leave=False):
                topic_id = topic.get("id")
                topic_title_list_view = topic.get("title", f"Untitled_Topic_{topic_id}")
                if not topic_id:
                    logging.warning(f"Topic data missing 'id' in category {category_id}, page {page+1}. Skipping.")
                    error_count += 1
                    continue
                temp_filepath_check = self.get_topic_filepath(topic_title_list_view, topic_id, current_path_parts)
                if os.path.exists(temp_filepath_check):
                    logging.debug(f"Topic {topic_id} ('{topic_title_list_view[:30]}...') already exists at {temp_filepath_check}. Skipping.")
                    skipped_count += 1
                    continue
                logging.debug(f"Processing topic: {topic_title_list_view} (ID: {topic_id})")
                self._topic_json_cache.pop(topic_id, None)
                json_text, json_dict = self.get_topic_json(topic_id)
                metadata = self._extract_metadata_from_json(json_dict, topic_id)
                parent_id = category_data.get("parent_category_id")
                if parent_id is not None:
                    if len(current_path_parts) > 1:
                        metadata['category_id'] = parent_id
                        metadata['category_name'] = current_path_parts[-2]
                        metadata['subcategory_id'] = category_id
                        metadata['subcategory_name'] = category_name
                    else:
                        logging.warning(f"Subcategory {category_name} (ID: {category_id}) has parent ID {parent_id} but path '{log_cat_path}' is too short.")
                        metadata['category_id'] = category_id
                        metadata['category_name'] = category_name
                else:
                    metadata['category_id'] = category_id
                    metadata['category_name'] = category_name
                    metadata['subcategory_id'] = None
                    metadata['subcategory_name'] = None
                raw_markdown = self.get_topic_raw_markdown(topic_id)
                if raw_markdown is not None:
                    save_title = metadata.get("topic_title", topic_title_list_view)
                    converted_markdown = self.convert_markdown_images(raw_markdown, topic_id)
                    self.save_markdown(save_title, topic_id, converted_markdown,
                                       current_path_parts, metadata)
                    processed_count += 1
                else:
                    logging.warning(f"Could not retrieve raw markdown for topic {topic_id}. Skipping save.")
                    error_count += 1
            page += 1
        if processed_count > 0 or skipped_count > 0 or error_count > 0:
            logging.info(f"Finished scraping direct topics for category '{log_cat_path}'. Processed: {processed_count}, Skipped: {skipped_count}, Errors: {error_count}")

    def scrape_category_and_subcategories(self,
                                          category_data: Dict[str, Any],
                                          current_path_parts: List[str],
                                          enabled_category_ids: Optional[Set[int]] = None):
        """
        Recursively scrapes direct topics of a category and then processes its subcategories.
        """
        cat_id = category_data.get("id")
        cat_name = category_data.get("name", f"Unnamed_{cat_id}")
        if not cat_id:
            logging.error(f"Cannot process category, missing ID. Data: {category_data}, Path: {current_path_parts}")
            return
        if enabled_category_ids is not None and cat_id not in enabled_category_ids:
            logging.info(f"Skipping category '{'/'.join(current_path_parts)}' (ID: {cat_id}) as it's not in the enabled list.")
            return
        log_cat_path = "/".join(current_path_parts)
        logging.debug(f"Processing category structure for: '{log_cat_path}' (ID: {cat_id})")
        self.scrape_topics_in_category(category_data, current_path_parts)
        subcategories = category_data.get("subcategories", [])
        if subcategories:
            logging.debug(f"Found {len(subcategories)} subcategories under '{log_cat_path}'. Processing recursively.")
            for subcat_data in subcategories:
                subcat_id = subcat_data.get("id")
                subcat_name = subcat_data.get("name", f"Unnamed_{subcat_id}")
                if not subcat_id:
                    logging.warning(f"Subcategory data under '{log_cat_path}' is missing 'id'. Skipping recursion.")
                    continue
                next_path_parts = current_path_parts + [subcat_name]
                self.scrape_category_and_subcategories(
                    category_data=subcat_data,
                    current_path_parts=next_path_parts,
                    enabled_category_ids=enabled_category_ids
                )
        else:
            logging.debug(f"No subcategories found under '{log_cat_path}'.")

    def run(self, enabled_category_ids: Optional[List[int]] = None):
        """Runs the full scraping process: login, fetch categories, scrape topics."""
        try:
            logging.info("Starting Discourse scraper...")
            if not self.auth_required:
                logging.info("Authentication is not required for this Discourse instance.")
            else:
                self.login()
                logging.info("Authentication is required. Attempting to log in...")

            categories_hierarchy = self.get_categories()
            if not categories_hierarchy:
                logging.warning("No categories found or failed to build category hierarchy. Exiting.")
                return
            enabled_ids_set: Optional[Set[int]] = None
            if enabled_category_ids is not None:
                valid_ids = {int(id_val) for id_val in enabled_category_ids if isinstance(id_val, (int, str)) and str(id_val).isdigit()}
                if len(valid_ids) != len(enabled_category_ids):
                    logging.warning("Some values in 'enabled_category_ids' were invalid and ignored.")
                if valid_ids:
                    enabled_ids_set = valid_ids
                    logging.info(f"Scraping enabled only for category IDs: {enabled_ids_set}")
                else:
                    logging.warning("Empty or invalid 'enabled_category_ids' provided. Scraping will likely do nothing.")
            else:
                logging.info("Scraping all accessible categories.")
            logging.info("Starting recursive topic scraping process...")
            for cat_id, top_level_cat_data in categories_hierarchy.items():
                cat_name = top_level_cat_data.get("name", f"Unnamed_{cat_id}")
                initial_path = [cat_name]
                self.scrape_category_and_subcategories(
                    category_data=top_level_cat_data,
                    current_path_parts=initial_path,
                    enabled_category_ids=enabled_ids_set
                )
            logging.info("Scraping process finished.")
        except Exception as e:
            logging.critical(f"An unrecoverable error occurred during the scraping run: {e}", exc_info=True)
            sys.exit(1)


def load_config(config_file: str) -> dict:
    """Loads the scraper configuration from a JSON file."""
    try:
        with open(config_file, "r", encoding="utf-8") as f:
            config = json.load(f)
        logging.info(f"Loaded configuration from {config_file}")
        auth_required = config.get("auth_required", False)
        required_keys = ["base_url"]
        if auth_required:
            required_keys += ["username", "password"]

        missing_keys = [key for key in required_keys if key not in config or not config[key]]
        if missing_keys:
            raise ValueError(f"Config file '{config_file}' missing or has empty required keys: {', '.join(missing_keys)}")
        if "rate_delay" in config:
            try:
                float(config["rate_delay"])
            except (ValueError, TypeError):
                raise ValueError("Config error: 'rate_delay' must be a number.")
        if "enabled_category_ids" in config and not isinstance(config["enabled_category_ids"], (list, type(None))):
            raise ValueError("Config error: 'enabled_category_ids' must be a list of IDs or null/absent.")
        return config
    except FileNotFoundError:
        logging.error(f"Configuration file not found: {config_file}")
        raise
    except json.JSONDecodeError as e:
        logging.error(f"Error decoding JSON from config file {config_file}: {e}")
        raise
    except ValueError as e:
        logging.error(f"Configuration error: {e}")
        raise
    except Exception as e:
        logging.error(f"An unexpected error occurred loading config {config_file}: {e}")
        raise


def main():
    parser = argparse.ArgumentParser(
        description="Scrape Discourse forum topics and save as nested markdown files with metadata."
    )
    parser.add_argument(
        "--config",
        type=str,
        help="Path to the JSON configuration file",
        required=True
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose debug logging"
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        help="Override the output directory specified in the config file.",
        default=None
    )
    parser.add_argument(
        "--session-file",
        type=str,
        help="Override the session persistence file specified in the config file.",
        default=None
    )
    args = parser.parse_args()
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.info("Verbose logging enabled.")
    else:
        logging.getLogger().setLevel(logging.INFO)
    try:
        config = load_config(args.config)
        output_dir = args.output_dir if args.output_dir else config.get("output_dir", "scraped")
        session_file = args.session_file if args.session_file else config.get("session_file", "session.pkl")
        rate_delay = float(config.get("rate_delay", 1.0))
        scraper = DiscourseScraper(
            base_url=config["base_url"],
            auth_required=config.get("auth_required", True),
            username=config["username"],
            password=config["password"],
            passcode=config.get("passcode"),
            rate_delay=rate_delay,
            output_dir=output_dir,
            session_file=session_file
        )
        enabled_category_ids = config.get("enabled_category_ids")
        scraper.run(enabled_category_ids=enabled_category_ids)
    except FileNotFoundError:
        print(f"Error: Configuration file '{args.config}' not found.", file=sys.stderr)
        sys.exit(1)
    except (ValueError, json.JSONDecodeError) as e:
        print(f"Error loading or validating configuration '{args.config}': {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"An critical error occurred: {e}", file=sys.stderr)
        logging.critical(f"Unhandled exception terminated the script: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()

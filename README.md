# Discourse Forum Scraper

This project is a Python-based tool for scraping topics and posts from a Discourse forum. It saves each topic as a Markdown file with YAML front matter metadata, organized by category and subcategory.

## Features

- Authenticates (if required) and maintains session persistence.
- Recursively fetches all categories and subcategories.
- Downloads all topics in enabled categories as Markdown files.
- Preserves topic metadata (title, author, tags, timestamps, etc.).
- Converts Discourse image links to absolute URLs.
- Supports configuration via a JSON file.

## Requirements

- Python 3.7+
- Dependencies: `requests`, `tqdm`, `base62`

Install dependencies:
```bash
pip install -r requirements.txt
```

## Configuration

Edit `config.json` to set:
- `base_url`: Discourse forum URL
- `auth_required`: `true` if login is needed
- `username`/`password`: Your Discourse credentials (if required)
- `output_dir`: Directory to save scraped files
- `enabled_category_ids`: List of category IDs to scrape

Example:
```json
{
  "base_url": "https://forum.example.com",
  "auth_required": true,
  "username": "youruser",
  "password": "yourpass",
  "output_dir": "scraped",
  "enabled_category_ids": [1, 2, 3]
}
```

## Usage

To run the scraper:
```bash
python3 main.py --config config.json
```

Optional arguments:
- `--output-dir DIR` — override output directory
- `--session-file FILE` — override session file
- `-v` or `--verbose` — enable debug logging

Or use the Makefile:
```bash
make scrap           # Start the scraping process
make merge           # Merge all markdown files by directory into the 'merged' folder
make clean-scraped   # Remove all scraped files
make clean-merged    # Remove all merged files
make help            # Show help and available targets
```

## Output

- Scraped markdown files are saved in the scraped directory, organized by category/subcategory.
- Merged markdown files are generated in the merged directory, with one file per source directory.
- Each file includes YAML front matter with topic metadata (for scraped files) and a header (for merged files).

## License

MIT License (or specify your license here).

---
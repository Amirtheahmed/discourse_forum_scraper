# Makefile for Discourse Documentation Scraper

# Variables
SCRAPED_DIR := scraped

.PHONY: scrap
scrap:
	python3 main.py --config config.json

# Clean up scraped files
.PHONY: clean
clean:
	@echo "Cleaning up scraped files..."
	@if [ -d "$(SCRAPED_DIR)" ]; then \
			rm -rf $(SCRAPED_DIR)/*.md; \
			echo "Cleaned $(SCRAPED_DIR) directory"; \
	else \
			echo "No $(SCRAPED_DIR) directory found"; \
	fi

# Help target
.PHONY: help
help:
	@echo "Discourse Documentation Scraper"
	@echo "=========================="
	@echo ""
	@echo "Available targets:"
	@echo "  scrap   - Start the scraping process"
	@echo "  clean   - Remove all scraped files"
	@echo "  help    - Show this help message"
	@echo ""
	@echo "Usage:"
	@echo "  make          # Run the scraping process"
	@echo "  make clean    # Clean up scraped files"
	@echo ""
	@echo "Output: All scraped files will be placed in the '$(MERGED_DIR)' directory"
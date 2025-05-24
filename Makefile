# Makefile for Discourse Documentation Scraper

# Variables
SCRAPED_DIR := scraped
MERGED_DIR := merged
EXCLUDE_DIRS := .git .venv $(MERGED_DIR)

.PHONY: scrap
scrap:
	python3 main.py --config config.json

# Clean up scraped files
.PHONY: clean-scraped
clean-scraped:
	@echo "Cleaning up scraped files..."
	@if [ -d "$(SCRAPED_DIR)" ]; then \
			rm -rf $(SCRAPED_DIR)/*.md; \
			echo "Cleaned $(SCRAPED_DIR) directory"; \
	else \
			echo "No $(SCRAPED_DIR) directory found"; \
	fi

# Main merge target
.PHONY: merge
merge: $(MERGED_DIR)
	@echo "Starting markdown file merge process..."
	@$(MAKE) -s merge-directories
	@echo "Merge complete! Check the '$(MERGED_DIR)' directory for results."

# Find and merge directories containing markdown files
.PHONY: merge-directories
merge-directories:
	@# Find all directories containing .md files, excluding specified directories
	@for dir in $$(find . -type f -name "*.md" -exec dirname {} \; | \
		grep -v -E "($(shell echo $(EXCLUDE_DIRS) | sed 's/ /|/g'))" | \
		sort -u); do \
		if [ "$$dir" != "." ]; then \
			$(MAKE) -s merge-single-directory DIR="$$dir"; \
		fi; \
	done
	@# Handle root level markdown files
	@if ls *.md >/dev/null 2>&1; then \
		$(MAKE) -s merge-single-directory DIR="."; \
	fi

# Merge markdown files in a single directory
.PHONY: merge-single-directory
merge-single-directory:
	@if [ -z "$(DIR)" ]; then \
		echo "Error: DIR variable not set"; \
		exit 1; \
	fi
	@# Skip if no markdown files in directory
	@if ! ls $(DIR)/*.md >/dev/null 2>&1; then \
		exit 0; \
	fi
	@# Create output filename based on directory path
	@if [ "$(DIR)" = "." ]; then \
		output_file="$(MERGED_DIR)/root.md"; \
	else \
		output_file="$(MERGED_DIR)/$$(echo '$(DIR)' | sed 's|^\./||' | sed 's|/|_|g').md"; \
	fi; \
	echo "Merging files in $(DIR) -> $$output_file"; \
	echo "# $$(echo '$(DIR)' | sed 's|^\./||' | tr '/' ' ' | sed 's/\b\w/\U&/g') Documentation" > "$$output_file"; \
	echo "" >> "$$output_file"; \
	echo "_This document contains merged content from all markdown files in the $(DIR) directory._" >> "$$output_file"; \
	echo "" >> "$$output_file"; \
	echo "---" >> "$$output_file"; \
	echo "" >> "$$output_file"; \
	for file in $(DIR)/*.md; do \
		if [ -f "$$file" ]; then \
			echo "## $$(basename "$$file" .md | sed 's/-/ /g' | sed 's/\b\w/\U&/g')" >> "$$output_file"; \
			echo "" >> "$$output_file"; \
			echo "_Source: $$file_" >> "$$output_file"; \
			echo "" >> "$$output_file"; \
			cat "$$file" >> "$$output_file"; \
			echo "" >> "$$output_file"; \
			echo "---" >> "$$output_file"; \
			echo "" >> "$$output_file"; \
		fi; \
	done

# Clean up merged files
.PHONY: clean-merged
clean-merged:
	@echo "Cleaning up merged files..."
	@if [ -d "$(MERGED_DIR)" ]; then \
		rm -rf $(MERGED_DIR)/*.md; \
		echo "Cleaned $(MERGED_DIR) directory"; \
	else \
		echo "No $(MERGED_DIR) directory found"; \
	fi

# Help target
.PHONY: help
help:
	@echo "Discourse Documentation Scraper"
	@echo "=========================="
	@echo ""
	@echo "Available targets:"
	@echo "  scrap   - Start the scraping process"
	@echo "  merge   		- Merge all markdown files by directory"
	@echo "  clean-merged   - Remove all merged files"
	@echo "  clean-scraped   - Remove all scraped files"
	@echo "  help    - Show this help message"
	@echo ""
	@echo "Usage:"
	@echo "  make          # Run the scraping process"
	@echo "  make scrap         # Run the scraping process"
	@echo "  make clean-scraped    # Clean up scraped files"
	@echo "  make merge    # Clean up merged files"
	@echo "  make clean-merged    # Clean up merged files"
	@echo ""
	@echo "Output: All scraped files will be placed in the '$(MERGED_DIR)' directory"
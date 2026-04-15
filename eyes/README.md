# Week 6 — Network Interception & Eyes Component

## What was built

- `network.py` — intercepts all HTTP requests and responses made by the browser
- `eyes/__init__.py` — combines Vision (Week 5) and Network into a unified `PageState` object

## New files

```
src/eyes/
├── __init__.py     ← Eyes class + PageState dataclass
└── network.py      ← NetworkInterceptor class
```

## Setup

```bash
pip install -r requirements.txt
playwright install chromium
docker run -p 3000:3000 bkimminich/juice-shop
```

## Running the tests

```bash
pytest tests/test_eyes.py -v -s
```

Expected result: 3 passed

## What the Eyes component captures

| Data                                  | Source     | Used for                  |
| ------------------------------------- | ---------- | ------------------------- |
| Screenshot                            | vision.py  | LLM visual context        |
| DOM (forms, buttons, links)           | vision.py  | LLM page understanding    |
| API requests/responses                | network.py | Route discovery           |
| Resource IDs (e.g. `/api/Products/5`) | network.py | IDOR test candidates      |
| Auth tokens in headers                | network.py | Role-based replay attacks |

# Week 5 - Vision Component - Eye Module Documentation

The Vision component provides comprehensive visual capture and DOM extraction capabilities for web security testing of Single Page Applications (SPAs) like OWASP Juice Shop.

## Features

### 1. Screenshot Capture

- **Full Page Screenshots**: Capture entire page including scrollable content with automatic stitching for SPAs
- **Element-Specific Screenshots**: Capture individual elements by selector
- Auto-generated filenames with timestamps
- All screenshots saved as PNG files

### 2. DOM Extraction

Comprehensive extraction of page structure including:

- **Forms**: All forms with fields, methods, actions, validation attributes **(Note: Angular Material forms without `<form>` tags won't be detected)**
- **Links**: All anchor tags with hrefs, text, and attributes
- **Buttons**: Button elements and input buttons
- **Inputs**: All input fields with types, validation rules
- **Navigation**: Nav elements and their link structures
- **Text Content**: Headings, paragraphs, lists
- **Scripts**: Script tags (inline and external)
- **Images**: Image elements with src, alt, dimensions
- **Structure**: Header, footer, main, aside, sections
- **Interactive Elements**: Clickable elements with visibility and position
- **Metadata**: Meta tags, page title, viewport info

### 3. Selector Generation

Each extracted element includes a CSS selector for the "hand" component to interact with:

- Prefers ID selectors when available
- Falls back to name attributes
- Uses class-based selectors
- Provides tag-based selectors as last resort

**Important Limitations:**

- Selectors are generated from static HTML parsed by BeautifulSoup
- Dynamic attributes added by JavaScript (like `aria-label`, `data-*`) are **not captured**
- For SPAs, some selectors may not be unique enough (e.g., Angular's dynamically generated class names)

### 4. LLM-Friendly Output

- JSON format with key-value pairs
- Text summaries formatted for LLM consumption
- Hierarchical structure for easy parsing
- Separate summary files for quick reference

## Installation (Optional)

### Required Dependencies

```bash
pip install playwright beautifulsoup4 Pillow
playwright install chromium
```

## Usage

### Basic Usage

```python
# might need to modify
from src.hands.browser import BrowserManager
from src.eyes.eye import Vision
from config.settings import SCREENSHOTS_DIR

# Initialize browser and vision
browser = BrowserManager()
browser.launch()
browser.navigate()

vision = Vision(browser.page, SCREENSHOTS_DIR)

# Capture screenshots
full_page = vision.capture_full_page("my_page_full")
viewport = vision.capture_viewport("my_page_viewport")
element = vision.capture_element("img.logo", "login_btn")

# Extract DOM
dom_data = vision.extract_dom()

# Save to file
vision.save_dom_to_file(dom_data, "my_page_dom")

# Get LLM summary
summary = vision.summarize_for_llm(dom_data)
print(summary)

browser.close()
```

### Running Tests

```bash
# Make sure Juice Shop is running with docker
cd tests
python test_eye.py
```

This will test the Vision component on various Juice Shop pages:

1. Home/Landing page
2. Login page
3. Registration page
4. Search results
5. Product detail
6. About page
7. Contact page

### Output Files

After running tests, you'll find in the `screenshots/` directory:

- `*_full.png` - Full page screenshots (stitched together for scrollable content)
- `*_element.png` - Element screenshots
- `*_dom.json` - Complete DOM data in JSON
- `*_summary.txt` - LLM-friendly text summaries

## Known Issues and Limitations

### 1. Forms Detection

**Issue:** Form count is often 0 even when forms are present on the page.

**Cause:** Modern SPAs like Juice Shop use Angular Material (`mat-form-field`) instead of traditional HTML `<form>` tags. BeautifulSoup only detects actual `<form>` elements.

### 2. Dynamic Attributes Not Captured

**Issue:** Attributes like `aria-label`, `data-*`, and other JavaScript-added attributes are missing from DOM extraction.

**Cause:** BeautifulSoup parses static HTML before JavaScript executes. Angular/React add these attributes dynamically.

### 3. Non-Unique Selectors

**Issue:** Multiple elements may have the same generated selector (e.g., `img.mat-mdc-card-image.mdc-card__media.img-responsive.img-thumbnail`)

**Cause:** Angular/Material generates similar class combinations for similar components.

### 4. Full Page Screenshots for SPAs

**Issue:** Full page screenshots may show repeated sections or not capture all content.

**Cause:** SPAs use internal scrollable containers (like `.mat-sidenav-content`) rather than document-level scrolling.

**Current Implementation:** The component now uses manual stitching to handle scrollable containers properly.

### 5. Hidden/Disabled Elements

**Issue:** Some buttons appear in the DOM but can't be interacted with.

**Cause:** Elements with classes like `mat-mdc-button-disabled` or `mat-mdc-button-disabled-interactive` are not clickable.

### Vision Class

#### `__init__(page: Page, screenshots_dir: Path)`

Initialize Vision component with Playwright page and screenshot directory.

#### `capture_full_page(filename: str = None) -> Path`

Capture full page screenshot including all scrollable content.

- **Returns**: Path to saved screenshot

#### `capture_element(selector: str, filename: str = None) -> Path`

Capture screenshot of a specific element.

- **Args**:
  - `selector`: CSS selector for element
  - `filename`: Optional filename (auto-generated if not provided)
- **Returns**: Path to saved screenshot

#### `extract_dom() -> Dict[str, Any]`

Extract comprehensive DOM structure and content.

- **Returns**: Dictionary containing complete DOM analysis

#### `save_dom_to_file(dom_data: Dict[str, Any], filename: str = None) -> Path`

Save DOM data to JSON file.

- **Returns**: Path to saved JSON file

#### `summarize_for_llm(dom_data: Dict[str, Any]) -> str`

Create concise summary of DOM for LLM consumption.

- **Returns**: Formatted string summary

## DOM Data Structure

```json
{
  "url": "http://localhost:3000",
  "title": "Page Title",
  "timestamp": "2024-02-16T10:30:00",
  "viewport": {
    "width": 1280,
    "height": 720
  },
  "metadata": {
    "description": "...",
    "keywords": "...",
    "meta_tags": [...]
  },
  "forms": [
    {
      "index": 0,
      "id": "loginForm",
      "action": "/login",
      "method": "POST",
      "selector": "#loginForm",
      "fields": [
        {
          "name": "email",
          "type": "email",
          "required": true,
          "selector": "input[name='email']"
        }
      ]
    }
  ],
  "links": [...],
  "buttons": [...],
  "inputs": [...],
  "navigation": [...],
  "text_content": {
    "headings": [...],
    "paragraphs": [...],
    "lists": [...]
  },
  "scripts": [...],
  "images": [...],
  "structure": {...},
  "interactive_elements": [...]
}
```

## Integration with Hand Component

The Vision component provides selectors for each element, making it easy for the "hand" component to interact:

```python
# Extract DOM
dom_data = vision.extract_dom()

# Get login button selector
for button in dom_data['buttons']:
    if 'login' in button['text'].lower():
        login_selector = button['selector']

# Use with hand component
browser.click(login_selector)

# Get form field selectors
for form in dom_data['forms']:
    for field in form['fields']:
        if field['name'] == 'email':
            browser.fill(field['selector'], 'test@example.com')
```

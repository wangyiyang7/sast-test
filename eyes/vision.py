"""
Vision module for web page analysis and extraction.
Provides screenshot capture and comprehensive DOM extraction capabilities.
"""

import io
import json
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, List,  Any
from PIL import Image
from playwright.sync_api import Page
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

class Vision:
    """Handles visual capture and DOM extraction for web pages."""
    
    def __init__(self, page: Page, screenshots_dir: Path):
        """
        Initialize Vision component.
        
        Args:
            page: Playwright Page object
            screenshots_dir: Directory to save screenshots
        """
        self.page = page
        self.screenshots_dir = Path(screenshots_dir)
        self.screenshots_dir.mkdir(parents=True, exist_ok=True)
    
    def capture_full_page(self, filename: str = None) -> Path:
        """Capture full page by manual scrolling and stitching."""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"fullpage_{timestamp}"
        
        filepath = self.screenshots_dir / f"{filename}.png"
        
        # Scroll to top first
        self.page.evaluate("""
            () => {
                const container = document.querySelector('.mat-sidenav-content') || document.documentElement;
                container.scrollTo(0, 0);
            }
        """)
        self.page.wait_for_timeout(300)
        
        # Get container info
        container_info = self.page.evaluate("""
            () => {
                const container = document.querySelector('.mat-sidenav-content') || document.documentElement;
                return {
                    scrollHeight: container.scrollHeight,
                    clientHeight: container.clientHeight
                };
            }
        """)
        
        scroll_height = container_info['scrollHeight']
        viewport_height = container_info['clientHeight']
        
        # If no scrolling needed
        if scroll_height <= viewport_height:
            self.page.screenshot(path=str(filepath), full_page=False)
            return filepath
        
        # Collect screenshots while scrolling
        screenshots = []
        scroll_positions = []
        current_position = 0
        
        while current_position < scroll_height:
            # Scroll to position
            self.page.evaluate(f"""
                () => {{
                    const container = document.querySelector('.mat-sidenav-content') || document.documentElement;
                    container.scrollTo(0, {current_position});
                }}
            """)
            self.page.wait_for_timeout(200)
            
            # Get actual scroll position (might be less than requested at the end)
            actual_position = self.page.evaluate("""
                () => {
                    const container = document.querySelector('.mat-sidenav-content') || document.documentElement;
                    return container.scrollTop;
                }
            """)
            
            # Capture viewport
            screenshot_bytes = self.page.screenshot(full_page=False)
            screenshots.append(Image.open(io.BytesIO(screenshot_bytes)))
            scroll_positions.append(actual_position)
            
            # Move to next position
            current_position += viewport_height
            
            # Stop if we can't scroll anymore
            if len(scroll_positions) > 1 and scroll_positions[-1] == scroll_positions[-2]:
                break
        
        # Stitch images together accounting for scroll positions
        if len(screenshots) == 1:
            screenshots[0].save(filepath)
            return filepath
        
        # Calculate total height based on last scroll position + viewport
        # Cast to int — JS scrollTop returns float, but PIL requires integer dimensions
        total_height = int(scroll_positions[-1] + screenshots[-1].height)
        stitched = Image.new('RGB', (screenshots[0].width, total_height))
        
        # Paste images at their correct positions
        for i, (img, pos) in enumerate(zip(screenshots, scroll_positions)):
            stitched.paste(img, (0, int(pos)))
        
        stitched.save(filepath)

        self._scroll_to_top()
        return filepath
    
    def _scroll_to_top(self) -> None:
        try:
            self.page.evaluate("""
                () => {
                    const container = document.querySelector('.mat-sidenav-content') || document.documentElement;
                    container.scrollTo(0, 0);
                }
            """)
        except Exception:
            pass
    
    def capture_element(self, selector: str, filename: str = None) -> Path:
        """
        Capture screenshot of specific element.
        
        Args:
            selector: CSS selector for the element
            filename: Optional custom filename (without extension)
            
        Returns:
            Path to saved screenshot
        """
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_selector = selector.replace(" ", "_").replace("#", "").replace(".", "")[:30]
            filename = f"element_{safe_selector}_{timestamp}"
        
        filepath = self.screenshots_dir / f"{filename}.png"
        element = self.page.locator(selector).first
        element.screenshot(path=str(filepath))
        
        return filepath
    
    def extract_dom(self) -> Dict[str, Any]:
        """
        Extract comprehensive DOM structure and content.
        
        Returns:
            Dictionary containing complete DOM analysis
        """
        # Get page HTML
        html_content = self.page.content()
        soup = BeautifulSoup(html_content, 'html.parser')
        
        dom_data = {
            "url": self.page.url,
            "title": self.page.title(),
            "timestamp": datetime.now().isoformat(),
            "viewport": self._get_viewport_info(),
            "metadata": self._extract_metadata(soup),
            "forms": self._extract_forms(soup),
            "links": self._extract_links(soup),
            "buttons": self._extract_buttons(soup),
            "inputs": self._extract_inputs(soup),
            "navigation": self._extract_navigation(soup),
            "text_content": self._extract_text_content(soup),
            "scripts": self._extract_scripts(soup),
            "images": self._extract_images(soup),
            "structure": self._extract_structure(soup),
            "interactive_elements": self._extract_interactive_elements()
        }
        
        return dom_data
    
    def _get_viewport_info(self) -> Dict[str, Any]:
        """Get viewport dimensions."""
        viewport = self.page.viewport_size
        return {
            "width": viewport.get("width"),
            "height": viewport.get("height")
        }
    
    def _extract_metadata(self, soup: BeautifulSoup) -> Dict[str, Any]:
        """Extract page metadata."""
        metadata = {
            "description": None,
            "keywords": None,
            "author": None,
            "charset": None,
            "viewport": None,
            "meta_tags": []
        }
        
        # Extract meta tags
        for meta in soup.find_all('meta'):
            meta_data = {
                "name": meta.get('name'),
                "property": meta.get('property'),
                "content": meta.get('content'),
                "http_equiv": meta.get('http-equiv')
            }
            metadata["meta_tags"].append(meta_data)
            
            # Extract common meta fields
            if meta.get('name') == 'description':
                metadata["description"] = meta.get('content')
            elif meta.get('name') == 'keywords':
                metadata["keywords"] = meta.get('content')
            elif meta.get('name') == 'author':
                metadata["author"] = meta.get('content')
            elif meta.get('charset'):
                metadata["charset"] = meta.get('charset')
            elif meta.get('name') == 'viewport':
                metadata["viewport"] = meta.get('content')
        
        return metadata
    
    def _extract_forms(self, soup: BeautifulSoup) -> List[Dict[str, Any]]:
        """Extract all forms with their fields and attributes."""
        forms = []
        
        for idx, form in enumerate(soup.find_all('form')):
            form_data = {
                "index": idx,
                "id": form.get('id'),
                "name": form.get('name'),
                "action": form.get('action'),
                "method": form.get('method', 'get').upper(),
                "enctype": form.get('enctype'),
                "class": form.get('class'),
                "selector": self._generate_selector(form),
                "fields": []
            }
            
            # Extract form fields
            for field in form.find_all(['input', 'textarea', 'select']):
                field_data = {
                    "tag": field.name,
                    "type": field.get('type', 'text'),
                    "name": field.get('name'),
                    "id": field.get('id'),
                    "placeholder": field.get('placeholder'),
                    "value": field.get('value'),
                    "required": field.has_attr('required'),
                    "disabled": field.has_attr('disabled'),
                    "readonly": field.has_attr('readonly'),
                    "class": field.get('class'),
                    "selector": self._generate_selector(field)
                }
                
                # For select elements, get options
                if field.name == 'select':
                    field_data["options"] = [
                        {
                            "value": opt.get('value'),
                            "text": opt.get_text(strip=True),
                            "selected": opt.has_attr('selected')
                        }
                        for opt in field.find_all('option')
                    ]
                
                form_data["fields"].append(field_data)
            
            forms.append(form_data)
        
        return forms
    
    def _extract_links(self, soup: BeautifulSoup) -> List[Dict[str, Any]]:
        """Extract all links."""
        links = []
        
        for idx, link in enumerate(soup.find_all('a')):
            link_data = {
                "index": idx,
                "href": link.get('href'),
                "text": link.get_text(strip=True),
                "title": link.get('title'),
                "target": link.get('target'),
                "id": link.get('id'),
                "class": link.get('class'),
                "rel": link.get('rel'),
                "selector": self._generate_selector(link)
            }
            links.append(link_data)
        
        return links
    
    def _extract_buttons(self, soup: BeautifulSoup) -> List[Dict[str, Any]]:
        """Extract all buttons and button-like elements."""
        buttons = []
        
        # Regular buttons
        for idx, button in enumerate(soup.find_all('button')):
            button_data = {
                "index": idx,
                "type": button.get('type', 'button'),
                "text": button.get_text(strip=True),
                "id": button.get('id'),
                "name": button.get('name'),
                "value": button.get('value'),
                "class": button.get('class'),
                "disabled": button.has_attr('disabled'),
                "form": button.get('form'),
                "selector": self._generate_selector(button)
            }
            buttons.append(button_data)
        
        # Input buttons
        for idx, inp in enumerate(soup.find_all('input', type=['button', 'submit', 'reset'])):
            button_data = {
                "index": len(buttons) + idx,
                "type": inp.get('type'),
                "text": inp.get('value', ''),
                "id": inp.get('id'),
                "name": inp.get('name'),
                "value": inp.get('value'),
                "class": inp.get('class'),
                "disabled": inp.has_attr('disabled'),
                "form": inp.get('form'),
                "selector": self._generate_selector(inp)
            }
            buttons.append(button_data)
        
        return buttons
    
    def _extract_inputs(self, soup: BeautifulSoup) -> List[Dict[str, Any]]:
        """Extract all input elements."""
        inputs = []
        
        for idx, inp in enumerate(soup.find_all('input')):
            input_data = {
                "index": idx,
                "type": inp.get('type', 'text'),
                "name": inp.get('name'),
                "id": inp.get('id'),
                "placeholder": inp.get('placeholder'),
                "value": inp.get('value'),
                "required": inp.has_attr('required'),
                "disabled": inp.has_attr('disabled'),
                "readonly": inp.has_attr('readonly'),
                "pattern": inp.get('pattern'),
                "min": inp.get('min'),
                "max": inp.get('max'),
                "minlength": inp.get('minlength'),
                "maxlength": inp.get('maxlength'),
                "autocomplete": inp.get('autocomplete'),
                "class": inp.get('class'),
                "selector": self._generate_selector(inp)
            }
            inputs.append(input_data)
        
        return inputs
    
    def _extract_navigation(self, soup: BeautifulSoup) -> List[Dict[str, Any]]:
        """Extract navigation elements."""
        navigation = []
        
        for idx, nav in enumerate(soup.find_all('nav')):
            nav_data = {
                "index": idx,
                "id": nav.get('id'),
                "class": nav.get('class'),
                "aria_label": nav.get('aria-label'),
                "selector": self._generate_selector(nav),
                "links": []
            }
            
            # Extract links within navigation
            for link in nav.find_all('a'):
                nav_data["links"].append({
                    "href": link.get('href'),
                    "text": link.get_text(strip=True),
                    "selector": self._generate_selector(link)
                })
            
            navigation.append(nav_data)
        
        return navigation
    
    def _extract_text_content(self, soup: BeautifulSoup) -> Dict[str, Any]:
        """Extract structured text content."""
        text_content = {
            "headings": [],
            "paragraphs": [],
            "lists": []
        }
        
        # Extract headings
        for level in range(1, 7):
            for idx, heading in enumerate(soup.find_all(f'h{level}')):
                text_content["headings"].append({
                    "level": level,
                    "text": heading.get_text(strip=True),
                    "id": heading.get('id'),
                    "class": heading.get('class'),
                    "selector": self._generate_selector(heading)
                })
        
        # Extract paragraphs
        for idx, para in enumerate(soup.find_all('p')):
            text_content["paragraphs"].append({
                "text": para.get_text(strip=True),
                "id": para.get('id'),
                "class": para.get('class'),
                "selector": self._generate_selector(para)
            })
        
        # Extract lists
        for idx, ul in enumerate(soup.find_all(['ul', 'ol'])):
            list_data = {
                "type": ul.name,
                "id": ul.get('id'),
                "class": ul.get('class'),
                "selector": self._generate_selector(ul),
                "items": []
            }
            
            for li in ul.find_all('li', recursive=False):
                list_data["items"].append({
                    "text": li.get_text(strip=True),
                    "selector": self._generate_selector(li)
                })
            
            text_content["lists"].append(list_data)
        
        return text_content
    
    def _extract_scripts(self, soup: BeautifulSoup) -> List[Dict[str, Any]]:
        """Extract script tags."""
        scripts = []
        
        for idx, script in enumerate(soup.find_all('script')):
            script_data = {
                "index": idx,
                "src": script.get('src'),
                "type": script.get('type'),
                "async": script.has_attr('async'),
                "defer": script.has_attr('defer'),
                "inline": script.get('src') is None,
                "content_length": len(script.string) if script.string else 0
            }
            scripts.append(script_data)
        
        return scripts
    
    def _extract_images(self, soup: BeautifulSoup) -> List[Dict[str, Any]]:
        """Extract image elements."""
        images = []
        
        for idx, img in enumerate(soup.find_all('img')):
            image_data = {
                "index": idx,
                "src": img.get('src'),
                "alt": img.get('alt'),
                "title": img.get('title'),
                "width": img.get('width'),
                "height": img.get('height'),
                "loading": img.get('loading'),
                "id": img.get('id'),
                "class": img.get('class'),
                "selector": self._generate_selector(img)
            }
            images.append(image_data)
        
        return images
    
    def _extract_structure(self, soup: BeautifulSoup) -> Dict[str, Any]:
        """Extract page structure elements."""
        structure = {
            "header": None,
            "footer": None,
            "main": None,
            "aside": [],
            "sections": []
        }
        
        # Header
        header = soup.find('header')
        if header:
            structure["header"] = {
                "id": header.get('id'),
                "class": header.get('class'),
                "selector": self._generate_selector(header)
            }
        
        # Footer
        footer = soup.find('footer')
        if footer:
            structure["footer"] = {
                "id": footer.get('id'),
                "class": footer.get('class'),
                "selector": self._generate_selector(footer)
            }
        
        # Main
        main = soup.find('main')
        if main:
            structure["main"] = {
                "id": main.get('id'),
                "class": main.get('class'),
                "selector": self._generate_selector(main)
            }
        
        # Aside
        for aside in soup.find_all('aside'):
            structure["aside"].append({
                "id": aside.get('id'),
                "class": aside.get('class'),
                "selector": self._generate_selector(aside)
            })
        
        # Sections
        for section in soup.find_all('section'):
            structure["sections"].append({
                "id": section.get('id'),
                "class": section.get('class'),
                "aria_label": section.get('aria-label'),
                "selector": self._generate_selector(section)
            })
        
        return structure
    
    def _extract_interactive_elements(self) -> List[Dict[str, Any]]:
        """Extract interactive elements using Playwright for accurate visibility."""
        interactive = []
        
        # Get all clickable elements
        selectors = [
            'a[href]',
            'button',
            'input[type="button"]',
            'input[type="submit"]',
            '[onclick]',
            '[role="button"]',
            '[tabindex]'
        ]
        
        for selector in selectors:
            try:
                elements = self.page.locator(selector).all()
                for idx, element in enumerate(elements):
                    try:
                        if element.is_visible():
                            interactive.append({
                                "selector": selector,
                                "index": idx,
                                "tag": element.evaluate("el => el.tagName.toLowerCase()"),
                                "text": element.inner_text()[:100] if element.inner_text() else "",
                                "is_enabled": element.is_enabled(),
                                "bounding_box": element.bounding_box()
                            })
                    except Exception as e:
                        logger.debug("Skipping element %s[%d]: %s", selector, idx, e)
                        continue
            except Exception as e:
                logger.debug("Skipping selector %s: %s", selector, e)
                continue
        
        return interactive
    
    def _generate_selector(self, element) -> str:
        """
        Generate the most specific CSS selector possible for an element.
        Priority: id > name attr > data-* attr > aria-label > tag+class > tag fallback.
        """
        tag = element.name or "unknown"

        # 1. ID is always unique
        if element.get('id'):
            return f"#{element['id']}"

        # 2. name attribute scoped to tag
        if element.get('name'):
            return f"{tag}[name='{element['name']}']"

        # 3. data-* attributes (stable in Angular/React apps like Juice Shop)
        for attr in element.attrs:
            if attr.startswith('data-') and element[attr]:
                return f"{tag}[{attr}='{element[attr]}']"

        # 4. aria-label (readable and often unique)
        if element.get('aria-label'):
            return f"{tag}[aria-label='{element['aria-label']}']"

        # 5. tag + all classes joined
        if element.get('class'):
            classes = '.'.join(c for c in element['class'] if c)
            if classes:
                return f"{tag}.{classes}"

        # 6. Last resort: tag name only (non-unique, caller should be aware)
        return tag
    
    def save_dom_to_file(self, dom_data: Dict[str, Any], filename: str = None) -> Path:
        """
        Save DOM data to JSON file.
        
        Args:
            dom_data: DOM extraction data
            filename: Optional custom filename (without extension)
            
        Returns:
            Path to saved JSON file
        """
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"dom_{timestamp}"
        
        filepath = self.screenshots_dir / f"{filename}.json"
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(dom_data, f, indent=2, ensure_ascii=False)
        
        return filepath
    
    def summarize_for_llm(self, dom_data: Dict[str, Any]) -> str:
        """
        Create a concise summary of DOM for LLM consumption.
        
        Args:
            dom_data: DOM extraction data
            
        Returns:
            Formatted string summary
        """
        summary = []
        
        summary.append(f"=== PAGE SUMMARY ===")
        summary.append(f"URL: {dom_data['url']}")
        summary.append(f"Title: {dom_data['title']}")
        summary.append("")
        
        # Forms summary
        if dom_data['forms']:
            summary.append(f"=== FORMS ({len(dom_data['forms'])}) ===")
            for form in dom_data['forms']:
                summary.append(f"Form {form['index']}: {form['method']} to {form['action']}")
                summary.append(f"  Selector: {form['selector']}")
                for field in form['fields']:
                    summary.append(f"  - {field['name']}: {field['type']} ({field['selector']})")
            summary.append("")
        
        # Links summary
        if dom_data['links']:
            summary.append(f"=== LINKS ({len(dom_data['links'])}) ===")
            for link in dom_data['links'][:10]:  # Limit to first 10
                summary.append(f"- {link['text']}: {link['href']} ({link['selector']})")
            if len(dom_data['links']) > 10:
                summary.append(f"... and {len(dom_data['links']) - 10} more links")
            summary.append("")
        
        # Buttons summary
        if dom_data['buttons']:
            summary.append(f"=== BUTTONS ({len(dom_data['buttons'])}) ===")
            for button in dom_data['buttons']:
                summary.append(f"- {button['text']}: {button['type']} ({button['selector']})")
            summary.append("")
        
        # Navigation summary
        if dom_data['navigation']:
            summary.append(f"=== NAVIGATION ({len(dom_data['navigation'])}) ===")
            for nav in dom_data['navigation']:
                summary.append(f"Nav {nav['index']}: {len(nav['links'])} links")
                for link in nav['links']:
                    summary.append(f"  - {link['text']}: {link['href']}")
            summary.append("")
        
        # Interactive elements
        if dom_data['interactive_elements']:
            summary.append(f"=== INTERACTIVE ELEMENTS ({len(dom_data['interactive_elements'])}) ===")
            for elem in dom_data['interactive_elements'][:15]:  # Limit to first 15
                summary.append(f"- {elem['tag']}: {elem['text'][:50]} ({elem['selector']})")
            summary.append("")
        
        return "\n".join(summary)

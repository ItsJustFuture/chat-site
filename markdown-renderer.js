"use strict";

/**
 * Markdown Renderer with Sanitization
 * 
 * This module provides safe markdown rendering using marked + DOMPurify.
 * It converts markdown to HTML and sanitizes the output to prevent XSS attacks.
 */

const { marked } = require("marked");
const { JSDOM } = require("jsdom");
const createDOMPurify = require("dompurify");

// Create DOMPurify instance with JSDOM window
const window = new JSDOM("").window;
const DOMPurify = createDOMPurify(window);

// Configure marked for safe rendering
marked.setOptions({
  breaks: true, // Convert \n to <br>
  gfm: true, // GitHub Flavored Markdown
  headerIds: false, // Disable header IDs
  mangle: false, // Don't mangle email addresses
});

// Configure DOMPurify to allow safe HTML elements
const ALLOWED_TAGS = [
  "p", "br", "strong", "em", "u", "s", "code", "pre",
  "a", "ul", "ol", "li", "blockquote", "h1", "h2", "h3", "h4", "h5", "h6",
  "table", "thead", "tbody", "tr", "th", "td", "hr", "del", "ins"
];

const ALLOWED_ATTR = ["href", "title", "class"];

/**
 * Render markdown text to safe HTML
 * @param {string} text - Raw markdown text
 * @returns {string} - Sanitized HTML
 */
function renderMarkdown(text) {
  if (!text || typeof text !== "string") {
    return "";
  }

  try {
    // Convert markdown to HTML
    const rawHtml = marked.parse(text, { async: false });
    
    // Sanitize HTML to prevent XSS
    const cleanHtml = DOMPurify.sanitize(rawHtml, {
      ALLOWED_TAGS,
      ALLOWED_ATTR,
      ALLOW_DATA_ATTR: false,
      ALLOW_UNKNOWN_PROTOCOLS: false,
    });

    return cleanHtml;
  } catch (error) {
    console.error("Markdown rendering error:", error);
    // Return escaped text as fallback
    return escapeHtml(text);
  }
}

/**
 * Escape HTML special characters
 * @param {string} text - Text to escape
 * @returns {string} - Escaped text
 */
function escapeHtml(text) {
  const map = {
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  };
  return String(text).replace(/[&<>"']/g, (m) => map[m]);
}

/**
 * Check if text contains markdown syntax
 * @param {string} text - Text to check
 * @returns {boolean} - True if markdown detected
 */
function hasMarkdownSyntax(text) {
  if (!text || typeof text !== "string") {
    return false;
  }

  // Check for common markdown patterns
  const markdownPatterns = [
    /\*\*.+?\*\*/,           // **bold**
    /\*.+?\*/,               // *italic*
    /__.+?__/,               // __bold__
    /_.+?_/,                 // _italic_
    /~~.+?~~/,               // ~~strikethrough~~
    /`[^`]+`/,               // `code`
    /```[\s\S]+?```/,        // ```code block```
    /^\s*[-*+]\s/m,          // - list item
    /^\s*\d+\.\s/m,          // 1. numbered list
    /^\s*>\s/m,              // > blockquote
    /^\s*#{1,6}\s/m,         // # heading
    /\[.+?\]\(.+?\)/,        // [link](url)
  ];

  return markdownPatterns.some(pattern => pattern.test(text));
}

module.exports = {
  renderMarkdown,
  escapeHtml,
  hasMarkdownSyntax,
};

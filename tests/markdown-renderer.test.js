"use strict";

const { renderMarkdown, escapeHtml, hasMarkdownSyntax } = require("../markdown-renderer");

describe("Markdown Renderer", () => {
  describe("renderMarkdown", () => {
    test("renders bold text", () => {
      const result = renderMarkdown("**bold text**");
      expect(result).toContain("<strong>bold text</strong>");
    });

    test("renders italic text", () => {
      const result = renderMarkdown("*italic text*");
      expect(result).toContain("<em>italic text</em>");
    });

    test("renders links", () => {
      const result = renderMarkdown("[GitHub](https://github.com)");
      expect(result).toContain('<a href="https://github.com">GitHub</a>');
    });

    test("renders code inline", () => {
      const result = renderMarkdown("`code here`");
      expect(result).toContain("<code>code here</code>");
    });

    test("renders code blocks", () => {
      const result = renderMarkdown("```\ncode block\n```");
      expect(result).toContain("<pre>");
      expect(result).toContain("<code>");
    });

    test("renders lists", () => {
      const result = renderMarkdown("- item 1\n- item 2");
      expect(result).toContain("<ul>");
      expect(result).toContain("<li>item 1</li>");
      expect(result).toContain("<li>item 2</li>");
    });

    test("sanitizes dangerous HTML", () => {
      const result = renderMarkdown("<script>alert('xss')</script>");
      expect(result).not.toContain("<script>");
      expect(result).not.toContain("alert");
    });

    test("sanitizes dangerous links", () => {
      const result = renderMarkdown("[click](javascript:alert('xss'))");
      expect(result).not.toContain("javascript:");
    });

    test("handles empty input", () => {
      expect(renderMarkdown("")).toBe("");
      expect(renderMarkdown(null)).toBe("");
      expect(renderMarkdown(undefined)).toBe("");
    });

    test("handles plain text without markdown", () => {
      const result = renderMarkdown("Hello world");
      expect(result).toContain("Hello world");
    });

    test("converts line breaks", () => {
      const result = renderMarkdown("line 1\nline 2");
      expect(result).toContain("line 1");
      expect(result).toContain("line 2");
    });

    test("renders strikethrough", () => {
      const result = renderMarkdown("~~strikethrough~~");
      expect(result).toContain("<del>strikethrough</del>");
    });
  });

  describe("escapeHtml", () => {
    test("escapes HTML special characters", () => {
      expect(escapeHtml("<script>")).toBe("&lt;script&gt;");
      expect(escapeHtml("&")).toBe("&amp;");
      expect(escapeHtml('"quotes"')).toBe("&quot;quotes&quot;");
      expect(escapeHtml("'apostrophe'")).toBe("&#39;apostrophe&#39;");
    });

    test("handles normal text", () => {
      expect(escapeHtml("Hello World")).toBe("Hello World");
    });
  });

  describe("hasMarkdownSyntax", () => {
    test("detects bold syntax", () => {
      expect(hasMarkdownSyntax("**bold**")).toBe(true);
      expect(hasMarkdownSyntax("__bold__")).toBe(true);
    });

    test("detects italic syntax", () => {
      expect(hasMarkdownSyntax("*italic*")).toBe(true);
      expect(hasMarkdownSyntax("_italic_")).toBe(true);
    });

    test("detects strikethrough", () => {
      expect(hasMarkdownSyntax("~~strike~~")).toBe(true);
    });

    test("detects code", () => {
      expect(hasMarkdownSyntax("`code`")).toBe(true);
      expect(hasMarkdownSyntax("```code block```")).toBe(true);
    });

    test("detects lists", () => {
      expect(hasMarkdownSyntax("- item")).toBe(true);
      expect(hasMarkdownSyntax("* item")).toBe(true);
      expect(hasMarkdownSyntax("1. item")).toBe(true);
    });

    test("detects links", () => {
      expect(hasMarkdownSyntax("[text](url)")).toBe(true);
    });

    test("detects headings", () => {
      expect(hasMarkdownSyntax("# Heading")).toBe(true);
      expect(hasMarkdownSyntax("## Heading 2")).toBe(true);
    });

    test("detects blockquotes", () => {
      expect(hasMarkdownSyntax("> quote")).toBe(true);
    });

    test("returns false for plain text", () => {
      expect(hasMarkdownSyntax("Hello world")).toBe(false);
      expect(hasMarkdownSyntax("")).toBe(false);
      expect(hasMarkdownSyntax(null)).toBe(false);
    });
  });
});

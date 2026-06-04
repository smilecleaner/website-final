/**
 * security.js — Smile Cleaning Ltd
 * Client-side security layer for static site + Formspree stack.
 *
 * Covers:
 *  1. Input sanitization (XSS prevention)
 *  2. Field-level validation with format checks
 *  3. Honeypot anti-spam (bot trap field)
 *  4. Client-side rate limiting (5 submissions / 60 s per session)
 *  5. Submission integrity check (detects headless/automated submissions)
 */

(function (global) {
  'use strict';

  /* ─── 1. SANITIZATION ──────────────────────────────────────────────────── */

  /**
   * Strip characters that could be used for XSS or injection.
   * For a static→Formspree stack the main risk is stored XSS if the Formspree
   * dashboard ever renders unsanitized HTML, and reflected XSS via URL params.
   */
  function sanitize(value) {
    if (typeof value !== 'string') return '';
    return value
      .trim()
      // Remove HTML tags
      .replace(/<[^>]*>/g, '')
      // Encode the five dangerous HTML entities
      .replace(/&/g, '&amp;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#x27;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      // Strip null bytes
      .replace(/\0/g, '')
      // Collapse excessive whitespace
      .replace(/\s{3,}/g, '  ')
      // Limit length — no field should need more than 2000 chars
      .slice(0, 2000);
  }

  /* ─── 2. FIELD VALIDATORS ───────────────────────────────────────────────── */

  const validators = {
    name: function (v) {
      // Letters, spaces, hyphens, apostrophes — 1–80 chars
      return /^[a-zA-ZÀ-ÿ '\-]{1,80}$/.test(v.trim());
    },
    email: function (v) {
      // RFC-5321 simplified — enough to catch obvious mistakes / injections
      return /^[^\s@]{1,64}@[^\s@]{1,255}\.[^\s@]{2,}$/.test(v.trim()) &&
        !/<|>|'|"|;/.test(v);
    },
    phone: function (v) {
      // NZ format: digits, spaces, +, -, (), 7–15 chars
      return /^[\d\s\+\-\(\)]{7,20}$/.test(v.trim());
    },
    text: function (v) {
      // General text — just ensure it's not empty after sanitize
      return sanitize(v).length > 0;
    },
    select: function (v) {
      return v && v !== '' && v !== 'undefined';
    }
  };

  /* ─── 3. RATE LIMITER ───────────────────────────────────────────────────── */

  var RATE_LIMIT = 5;           // max submissions
  var RATE_WINDOW = 60 * 1000;  // per 60 seconds (session-scoped)

  var _submissions = [];

  function isRateLimited() {
    var now = Date.now();
    // Drop entries outside the window
    _submissions = _submissions.filter(function (t) { return now - t < RATE_WINDOW; });
    return _submissions.length >= RATE_LIMIT;
  }

  function recordSubmission() {
    _submissions.push(Date.now());
  }

  /* ─── 4. HONEYPOT INJECTION ─────────────────────────────────────────────── */

  /**
   * Injects a visually hidden field. Bots fill every field — humans don't see it.
   * If the field has a value at submission time, we silently abort.
   */
  function injectHoneypot(form) {
    if (!form) return;
    var existing = form.querySelector('[data-honeypot]');
    if (existing) return;

    var wrapper = document.createElement('div');
    wrapper.setAttribute('aria-hidden', 'true');
    wrapper.style.cssText = 'position:absolute;left:-9999px;height:0;overflow:hidden;';

    var label = document.createElement('label');
    label.setAttribute('for', '_hp_website');
    label.textContent = 'Website (leave blank)';

    var input = document.createElement('input');
    input.type = 'text';
    input.id = '_hp_website';
    input.name = '_hp_website';
    input.tabIndex = -1;
    input.autocomplete = 'off';
    input.setAttribute('data-honeypot', '1');

    wrapper.appendChild(label);
    wrapper.appendChild(input);
    form.appendChild(wrapper);
  }

  function honeypotTripped(form) {
    if (!form) return false;
    var hp = form.querySelector('[data-honeypot]');
    return hp && hp.value.length > 0;
  }

  /* ─── 5. TIMING CHECK ───────────────────────────────────────────────────── */

  /**
   * Track when the form first became interactive. Bots submit within
   * milliseconds; a real human takes at least 3 seconds to fill a form.
   */
  var _formLoadTime = Date.now();

  function isSubmittedTooFast() {
    return (Date.now() - _formLoadTime) < 3000;
  }

  /* ─── PUBLIC API ─────────────────────────────────────────────────────────── */

  global.SmileSecurity = {

    sanitize: sanitize,

    validators: validators,

    /**
     * Call this on page load to set up the form's honeypot field.
     * @param {HTMLElement} form
     */
    initForm: function (form) {
      injectHoneypot(form);
      _formLoadTime = Date.now();
    },

    /**
     * Run all pre-submission security checks.
     * Returns { ok: true } or { ok: false, reason: string }
     * @param {HTMLElement} form
     */
    preSubmitCheck: function (form) {
      if (isSubmittedTooFast()) {
        return { ok: false, reason: 'submission_too_fast' };
      }
      if (honeypotTripped(form)) {
        return { ok: false, reason: 'honeypot' };
      }
      if (isRateLimited()) {
        return { ok: false, reason: 'rate_limited' };
      }
      return { ok: true };
    },

    /**
     * Sanitize an entire data object — call before sending to Formspree.
     * @param {Object} data
     * @returns {Object}
     */
    sanitizePayload: function (data) {
      var clean = {};
      Object.keys(data).forEach(function (k) {
        clean[k] = sanitize(String(data[k]));
      });
      return clean;
    },

    recordSubmission: recordSubmission
  };

})(window);

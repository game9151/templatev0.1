// ─────────────────────────────────────────────────────────────
//  /api/contact.js — Vercel Serverless Function
//
//  Receives the enquiry form, rejects bots (honeypot + Cloudflare
//  Turnstile), validates/cleans the input, then emails the business.
//
//  Environment variables (Vercel → Project → Settings → Environment Variables):
//    GMAIL_USER           Gmail address that SENDS the email (your agency inbox)
//    GMAIL_APP_PASSWORD   16-char Google "App Password" for that account
//    CLIENT_EMAIL         Where enquiries are delivered (comma-separate for 2+)
//    TURNSTILE_SECRET     Cloudflare Turnstile secret key (free) — strongly recommended
//    BUSINESS_NAME        e.g. "Summit Auto Works"          (shown in the email)
//    BRAND_ACCENT         optional, e.g. "#B8966A"          (email accent colour)
//    ALLOWED_HOSTS        optional, extra hostnames allowed to post here (comma-separated)
// ─────────────────────────────────────────────────────────────
'use strict';

const nodemailer = require('nodemailer');

const BUSINESS = process.env.BUSINESS_NAME || 'Website';
const ACCENT = /^#[0-9a-f]{6}$/i.test(process.env.BRAND_ACCENT || '') ? process.env.BRAND_ACCENT : '#B8966A';

const MAX = { name: 100, phone: 40, email: 200, vehicle: 120, message: 4000 };
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// ── Simple per-instance rate limit (5 enquiries / 10 min / IP). Not bullet-proof on
//    serverless (each instance has its own memory) but stops casual hammering. ──
const hits = new Map();
function rateLimited(ip) {
  const now = Date.now(), windowMs = 10 * 60 * 1000;
  const recent = (hits.get(ip) || []).filter(t => now - t < windowMs);
  recent.push(now);
  hits.set(ip, recent);
  if (hits.size > 500) for (const [k, v] of hits) if (!v.some(t => now - t < windowMs)) hits.delete(k);
  return recent.length > 5;
}

const oneLine = (v, max) => String(v ?? '').replace(/[\u0000-\u001f\u007f]+/g, ' ').replace(/\s+/g, ' ').trim().slice(0, max);
const multiLine = (v, max) => String(v ?? '').replace(/\r\n?/g, '\n').replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '').trim().slice(0, max);

function escHtml(str) {
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

module.exports = async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');

  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ error: 'Method not allowed' });
  }

  // ── Only accept posts from this site (blocks other websites using your form) ──
  const origin = req.headers.origin;
  if (origin) {
    let ok = false;
    try {
      const host = new URL(origin).host;
      const allowed = [req.headers.host, ...(process.env.ALLOWED_HOSTS || '').split(',').map(s => s.trim())].filter(Boolean);
      ok = allowed.includes(host);
    } catch (_) { /* malformed Origin */ }
    if (!ok) return res.status(403).json({ error: 'Forbidden' });
  }

  // ── Body ──
  let body = req.body;
  if (typeof body === 'string') { try { body = JSON.parse(body); } catch (_) { body = null; } }
  if (!body || typeof body !== 'object') return res.status(400).json({ error: 'Invalid request.' });

  // ── Honeypot: bots fill hidden fields, humans never see them. Pretend success. ──
  if (body.botField) return res.status(200).json({ ok: true });

  const ip = String(req.headers['x-forwarded-for'] || req.socket?.remoteAddress || 'unknown').split(',')[0].trim();
  if (rateLimited(ip)) return res.status(429).json({ error: 'Too many enquiries — please try again in a few minutes.' });

  // ── Clean + validate ──
  const name = oneLine(body.name, MAX.name);
  const phone = oneLine(body.phone, MAX.phone);
  const email = oneLine(body.email, MAX.email);
  const vehicle = oneLine(body.vehicle, MAX.vehicle);
  const message = multiLine(body.message, MAX.message);

  if (!name || !phone || !email || !message) return res.status(400).json({ error: 'Please fill in all required fields.' });
  if (!EMAIL_RE.test(email)) return res.status(400).json({ error: 'Please enter a valid email address.' });
  if (!/\d{6,}/.test(phone.replace(/[\s()+-]/g, ''))) return res.status(400).json({ error: 'Please enter a valid phone number.' });

  // ── Turnstile (fails CLOSED: if it's configured, it must pass) ──
  const secret = process.env.TURNSTILE_SECRET;
  if (secret) {
    const token = body['cf-turnstile-response'];
    if (!token) return res.status(400).json({ error: 'Please complete the verification check and try again.' });
    try {
      const ctl = new AbortController();
      const timer = setTimeout(() => ctl.abort(), 6000);
      const verify = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ secret, response: token, remoteip: ip }),
        signal: ctl.signal,
      });
      clearTimeout(timer);
      const data = await verify.json();
      if (!data.success) return res.status(400).json({ error: 'Verification failed. Please refresh the page and try again.' });
    } catch (err) {
      console.error('Turnstile verification error:', err && err.message);
      return res.status(503).json({ error: 'We couldn’t verify your submission right now.' });
    }
  } else {
    console.warn('TURNSTILE_SECRET is not set — spam protection is honeypot-only.');
  }

  // ── Email ──
  const { GMAIL_USER, GMAIL_APP_PASSWORD, CLIENT_EMAIL } = process.env;
  if (!GMAIL_USER || !GMAIL_APP_PASSWORD || !CLIENT_EMAIL) {
    console.error('Missing GMAIL_USER / GMAIL_APP_PASSWORD / CLIENT_EMAIL environment variables.');
    console.error('LEAD_NOT_SENT', JSON.stringify({ name, phone, email, vehicle, message }));
    return res.status(500).json({ error: 'Sorry, something went wrong on our end.' });
  }

  const row = (label, valueHtml, last) =>
    `<tr><td style="padding:10px 0;${last ? '' : 'border-bottom:1px solid #2a2a2a;'}color:#888;font-size:13px;width:110px;vertical-align:top;">${label}</td>` +
    `<td style="padding:10px 0;${last ? '' : 'border-bottom:1px solid #2a2a2a;'}color:#e8e4dc;font-size:14px;line-height:1.65;">${valueHtml}</td></tr>`;
  const link = (href, text) => `<a href="${href}" style="color:${ACCENT};text-decoration:none;">${escHtml(text)}</a>`;

  const html = `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:20px;background:#0a0a0a;font-family:Arial,Helvetica,sans-serif;">
  <div style="max-width:580px;margin:0 auto;">
    <div style="background:#141414;padding:24px 28px;border-left:3px solid ${ACCENT};">
      <p style="margin:0 0 4px;font-size:11px;letter-spacing:.18em;text-transform:uppercase;color:${ACCENT};">New Enquiry</p>
      <h1 style="margin:0;font-size:22px;color:#e8e4dc;font-weight:400;">${escHtml(BUSINESS)}</h1>
    </div>
    <div style="background:#1a1a1a;padding:28px;border:1px solid #2a2a2a;border-top:none;">
      <table style="width:100%;border-collapse:collapse;">
        ${row('Name', escHtml(name))}
        ${row('Phone', link('tel:' + escHtml(phone.replace(/[^\d+]/g, '')), phone))}
        ${row('Email', link('mailto:' + escHtml(email), email))}
        ${vehicle ? row('Vehicle', escHtml(vehicle)) : ''}
        ${row('Message', escHtml(message).replace(/\n/g, '<br>'), true)}
      </table>
    </div>
    <div style="background:#111;padding:14px 28px;border:1px solid #2a2a2a;border-top:none;">
      <p style="margin:0;color:#777;font-size:11px;">Hit <strong style="color:#aaa">Reply</strong> to respond directly to ${escHtml(name)} — their email is set as the reply-to address.</p>
    </div>
  </div>
</body></html>`;

  const text = [`New enquiry — ${BUSINESS}`, '', `Name: ${name}`, `Phone: ${phone}`, `Email: ${email}`, vehicle ? `Vehicle: ${vehicle}` : null, '', message, '', '(Reply to this email to respond to the customer.)']
    .filter(v => v !== null).join('\n');

  try {
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: { user: GMAIL_USER, pass: GMAIL_APP_PASSWORD },
      connectionTimeout: 8000, greetingTimeout: 8000, socketTimeout: 10000,
    });
    await transporter.sendMail({
      from: `"${BUSINESS.replace(/["\r\n]/g, '')} Website" <${GMAIL_USER}>`,
      to: CLIENT_EMAIL,
      replyTo: `"${name.replace(/["\r\n]/g, '')}" <${email}>`,
      subject: `New enquiry from ${name}${vehicle ? ' — ' + vehicle : ''}`,
      text,
      html,
    });
    return res.status(200).json({ ok: true });
  } catch (err) {
    console.error('Email send error:', err && err.message);
    // Last-resort backup so the lead isn't lost: it's in the Vercel runtime logs.
    console.error('LEAD_NOT_SENT', JSON.stringify({ name, phone, email, vehicle, message }));
    return res.status(500).json({ error: 'Sorry, we couldn’t send your enquiry.' });
  }
};

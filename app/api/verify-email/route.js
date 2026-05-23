// app/api/verify-email/route.js
import { NextResponse } from 'next/server';
import dns from 'dns/promises';

/**
 * Enterprise-grade Email Verification Engine
 * Handles syntax, disposable domains, MX records, and basic header spoofing detection.
 */

const DISPOSABLE_DOMAINS = new Set([
  'mailinator.com', 'yopmail.com', 'trashmail.com', '10minutemail.com', 'tempmail.com',
  'guerrillamail.com', 'temp-mail.org', 'throwawaymail.com', 'maildrop.cc', 'sharklasers.com',
  'getnada.com', 'tempinbox.com', 'dispostable.com', 'mailnesia.com', 'fakeinbox.com',
  'tempmail.net', 'emailondeck.com', 'grr.la', '10minutemail.net', 'guerrillamailblock.com',
  'mohmal.com', 'tempail.com', 'throwaway.email', 'disposablemail.com', 'mail7.io',
  // Add more as needed from reliable sources
]);

const EMAIL_REGEX = /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/i;

function extractDomain(email) {
  if (!email || typeof email !== 'string') return null;
  const atIndex = email.lastIndexOf('@');
  return atIndex > 0 ? email.slice(atIndex + 1).toLowerCase().trim() : null;
}

function checkSyntax(email) {
  if (!email || typeof email !== 'string') return false;
  return EMAIL_REGEX.test(email.trim());
}

function isDisposableDomain(domain) {
  if (!domain) return true;
  return DISPOSABLE_DOMAINS.has(domain);
}

async function checkMXRecords(domain) {
  if (!domain) return false;
  try {
    const mxRecords = await dns.resolveMx(domain);
    return mxRecords && mxRecords.length > 0;
  } catch (error) {
    // No MX records or DNS error
    return false;
  }
}

function analyzeHeaders(rawHeaders) {
  if (!rawHeaders || typeof rawHeaders !== 'string') {
    return {
      isSpoofed: false,
      spoofFlags: []
    };
  }

  const headersLower = rawHeaders.toLowerCase();
  const spoofFlags = [];

  if (headersLower.includes('spf=fail')) spoofFlags.push('SPF_FAIL');
  if (headersLower.includes('dkim=fail')) spoofFlags.push('DKIM_FAIL');
  if (headersLower.includes('dmarc=fail')) spoofFlags.push('DMARC_FAIL');

  // Additional heuristics
  const hasMultipleReceived = (headersLower.match(/received:/g) || []).length > 3;
  if (hasMultipleReceived) spoofFlags.push('SUSPICIOUS_RECEIVED_CHAIN');

  const isSpoofed = spoofFlags.length > 0;

  return { isSpoofed, spoofFlags };
}

export async function POST(request) {
  try {
    const body = await request.json();
    const { email, rawHeaders } = body;

    if (!email) {
      return NextResponse.json(
        { error: 'Email is required' },
        { status: 400 }
      );
    }

    const trimmedEmail = email.trim();
    const domain = extractDomain(trimmedEmail);

    // Step 1: Syntax Validation
    const isValidSyntax = checkSyntax(trimmedEmail);

    if (!isValidSyntax) {
      return NextResponse.json({
        email: trimmedEmail,
        emailRiskScore: 100,
        isValidSyntax: false,
        isDisposable: false,
        hasMxRecords: false,
        isSpoofed: false,
        flags: ['INVALID_SYNTAX'],
        message: 'Invalid email syntax'
      });
    }

    // Step 2: Disposable Check
    const isDisposable = isDisposableDomain(domain);

    // Step 3: MX Records
    const hasMxRecords = await checkMXRecords(domain);

    // Step 4: Header Analysis
    const headerAnalysis = analyzeHeaders(rawHeaders);
    const isSpoofed = headerAnalysis.isSpoofed;

    // Calculate Risk Score (0-100)
    let riskScore = 0;

    if (isDisposable) riskScore += 40;
    if (!hasMxRecords) riskScore += 35;
    if (isSpoofed) riskScore += 25;

    // Additional penalties
    if (domain && domain.length < 4) riskScore += 10;
    if (trimmedEmail.split('@')[0].length < 3) riskScore += 5;

    riskScore = Math.min(100, Math.max(0, riskScore));

    const flags = [];
    if (isDisposable) flags.push('DISPOSABLE_DOMAIN');
    if (!hasMxRecords) flags.push('NO_MX_RECORDS');
    if (isSpoofed) flags.push('HEADER_SPOOFING_DETECTED');
    if (headerAnalysis.spoofFlags.length > 0) {
      flags.push(...headerAnalysis.spoofFlags);
    }

    const result = {
      email: trimmedEmail,
      domain,
      emailRiskScore: riskScore,
      isValidSyntax: true,
      isDisposable,
      hasMxRecords,
      isSpoofed,
      flags,
      spoofDetails: headerAnalysis.spoofFlags,
      timestamp: new Date().toISOString(),
      message: riskScore > 70 
        ? 'High risk - likely scam or invalid' 
        : riskScore > 40 
          ? 'Medium risk' 
          : 'Low risk - appears legitimate'
    };

    return NextResponse.json(result);

  } catch (error) {
    console.error('Email verification error:', error);
    return NextResponse.json(
      { 
        error: 'Internal server error during verification',
        message: error.message 
      },
      { status: 500 }
    );
  }
}

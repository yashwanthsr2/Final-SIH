export function connectWebSocket(onMessage: (data: any) => void) {
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const host = window.location.host;
  const ws = new WebSocket(`${protocol}//${host}/ws/alerts`);

  ws.onmessage = (event) => {
    try {
      const parsed = JSON.parse(event.data);
      onMessage(parsed);
    } catch (e) {
      console.error("WS Parse Error", e);
    }
  };

  ws.onclose = () => {
    setTimeout(() => connectWebSocket(onMessage), 3000);
  };

  return ws;
}

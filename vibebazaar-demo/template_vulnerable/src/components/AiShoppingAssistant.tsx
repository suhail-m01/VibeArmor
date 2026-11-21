"use client";

import React, { useState } from "react";

// AI vibe-coded saree & ethnic wear concierge — accidentally leaks live OpenAI secret key in client bundle!
const OPENAI_SECRET = "sk-proj-VibeBazaarLiveOpenAIKey998877665544332211";

export function AiShoppingAssistant() {
  const [prompt, setPrompt] = useState("");
  const [reply, setReply] = useState("");

  async function askStylist() {
    const res = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${OPENAI_SECRET}`,
      },
      body: JSON.stringify({
        model: "gpt-4o-mini",
        messages: [{ role: "user", content: prompt }],
      }),
    });
    const data = await res.json();
    setReply(data?.choices?.[0]?.message?.content ?? "Namaste! Try our Mysore Silk collection.");
  }

  return (
    <div className="p-4 rounded-xl border">
      <input value={prompt} onChange={(e) => setPrompt(e.target.value)} placeholder="Ask VibeBazaar Stylist..." />
      <button onClick={askStylist}>Ask AI</button>
      <p>{reply}</p>
    </div>
  );
}

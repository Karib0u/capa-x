import { useRef, useState } from "react";

export default function DropZone({ onFile, error }: { onFile: (f: File) => void; error?: string | null }) {
  const input = useRef<HTMLInputElement>(null);
  const [over, setOver] = useState(false);
  const take = (f?: File) => f && onFile(f);
  const [demoError, setDemoError] = useState<string | null>(null);
  // A small harmless program bundled with the site (see demo/), so people can try the tool without a binary.
  const tryDemo = async () => {
    setDemoError(null);
    try {
      const res = await fetch(`${import.meta.env.BASE_URL}demo.exe`);
      if (!res.ok) throw new Error(`demo sample unavailable (${res.status})`);
      onFile(new File([await res.blob()], "capa-x-demo.exe"));
    } catch (e) {
      setDemoError(String((e as Error).message ?? e));
    }
  };

  return (
    <main className="landing">
      <div className="brand">capa<span>-x</span></div>
      <label
        className={"drop" + (over ? " over" : "")}
        onDragOver={(e) => { e.preventDefault(); setOver(true); }}
        onDragLeave={() => setOver(false)}
        onDrop={(e) => { e.preventDefault(); setOver(false); take(e.dataTransfer.files[0]); }}
      >
        <input ref={input} type="file" hidden onChange={(e) => take(e.target.files?.[0])} />
        <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
          <path d="M12 16V4m0 0L7 9m5-5 5 5M4 16v3a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1v-3" />
        </svg>
        <strong>Drop a binary to analyze</strong>
        <span>or click to browse · Windows PE (x86 / x64)</span>
      </label>
      <p className="demo">
        No binary at hand? <button type="button" onClick={tryDemo}>Try the demo sample</button>
        <small>an 8 KB program written for this demo</small>
      </p>
      {(error || demoError) && <p className="error">{error ?? demoError}</p>}
      <p className="fine">Analysis runs in your browser. Nothing is uploaded.</p>
    </main>
  );
}

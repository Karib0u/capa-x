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

  // The whole page takes a dropped file, not only the box.
  return (
    <main
      className={"landing" + (over ? " over" : "")}
      onDragOver={(e) => { e.preventDefault(); setOver(true); }}
      onDragLeave={(e) => { if (e.currentTarget === e.target || !e.currentTarget.contains(e.relatedTarget as Node)) setOver(false); }}
      onDrop={(e) => { e.preventDefault(); setOver(false); take(e.dataTransfer.files[0]); }}
    >
      <div className="brand">capa<span>-x</span></div>
      <section className="hero">
        <h1>Read a binary in your browser.</h1>
        <p>Capabilities, decompiled C and control flow for Windows executables.</p>
      </section>
      <label className="drop">
        <input ref={input} type="file" hidden onChange={(e) => take(e.target.files?.[0])} />
        <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
          <path d="M12 15V4m0 0L7.5 8.5M12 4l4.5 4.5M5 14v4.5A1.5 1.5 0 0 0 6.5 20h11a1.5 1.5 0 0 0 1.5-1.5V14" />
        </svg>
        <strong>Drop a file, or <u>browse</u></strong>
        <span>Windows PE · x86 / x64</span>
      </label>
      <button type="button" className="demo" onClick={tryDemo}>Try the demo sample <span aria-hidden>→</span></button>
      {(error || demoError) && <p className="error">{error ?? demoError}</p>}
      <p className="fine">Runs entirely on your device. Nothing is uploaded.</p>
    </main>
  );
}

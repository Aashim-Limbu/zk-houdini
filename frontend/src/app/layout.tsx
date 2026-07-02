import type { Metadata } from "next";
import { Archivo, Public_Sans, JetBrains_Mono } from "next/font/google";
import "./globals.css";

// Archivo is the institutional grotesque set heavy for display headlines.
// Public Sans carries running prose. JetBrains Mono is the proof/evidence voice
// for every exact value — digests, image ids, journals, contract addresses.
const archivo = Archivo({
  subsets: ["latin"],
  weight: ["500", "600", "700", "800"],
  variable: "--font-archivo",
  display: "swap",
});

const publicSans = Public_Sans({
  subsets: ["latin"],
  variable: "--font-public",
  display: "swap",
});

const jetbrainsMono = JetBrains_Mono({
  subsets: ["latin"],
  variable: "--font-jetbrains",
  display: "swap",
});

export const metadata: Metadata = {
  title: "ProofReceipt — pay for provable work, or get your money back",
  description:
    "An escrow on Stellar with no arbiter: USDC releases only when a zero-knowledge proof, verified on Soroban, shows the agreed program ran on your exact input. No proof, no payment — the buyer reclaims.",
  applicationName: "ProofReceipt",
  openGraph: {
    title: "ProofReceipt — pay for provable work, or get your money back",
    description:
      "When you pay for work you can't watch, settlement runs on trust or an arbiter. ProofReceipt replaces both with a proof, verified on Stellar. Verification is settlement.",
    type: "website",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html
      lang="en"
      data-scroll-behavior="smooth"
      className={`${archivo.variable} ${publicSans.variable} ${jetbrainsMono.variable} h-full antialiased`}
    >
      <body className="relative min-h-full flex flex-col overflow-x-hidden">
        {children}
      </body>
    </html>
  );
}

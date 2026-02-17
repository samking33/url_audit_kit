import type { Metadata } from 'next';
import { Bricolage_Grotesque, Space_Mono } from 'next/font/google';

import './globals.css';

const bricolage = Bricolage_Grotesque({
  subsets: ['latin'],
  variable: '--font-display',
  weight: ['400', '600', '700', '800'],
});

const spaceMono = Space_Mono({
  subsets: ['latin'],
  variable: '--font-mono',
  weight: ['400', '700'],
});

export const metadata: Metadata = {
  title: 'URL Audit Kit',
  description: 'Neo-Brutalist URL threat audit interface',
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className={`${bricolage.variable} ${spaceMono.variable}`}>{children}</body>
    </html>
  );
}

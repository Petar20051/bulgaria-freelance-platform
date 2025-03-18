// app/layout.tsx
import './styles/global.css';

export const metadata = {
  title: 'Bulgaria Freelance Platform',
  description: 'A localized freelance marketplace',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}

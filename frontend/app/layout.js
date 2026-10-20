import "./globals.css";

export const metadata = {
  title: "Pusat Triase Insiden Siber",
  description: "Dari ribuan baris log menjadi satu cerita serangan",
};

export default function RootLayout({ children }) {
  return (
    <html lang="id">
      <body>{children}</body>
    </html>
  );
}

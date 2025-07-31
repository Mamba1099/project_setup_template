export default function CoreLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <div className="flex flex-col min-h-screen bg-gray-50">
      <main className="flex items-center justify-center py-12 px-4">
        {children}
      </main>
    </div>
    );
}
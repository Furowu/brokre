class Brokre < Formula
  desc "AI-safe credential broker CLI"
  homepage "https://github.com/Furowu/brokre"
  version "0.1.6"

  if OS.mac? && Hardware::CPU.intel?
    url "https://github.com/Furowu/brokre/releases/download/v0.1.6/brokre-x86_64-apple-darwin.tar.gz"
    sha256 "92d6a656faf748f3b3df4f7d21563a5d366b74a10f5a3c537d959d074a0c8c97"
  elsif OS.mac? && Hardware::CPU.arm?
    url "https://github.com/Furowu/brokre/releases/download/v0.1.6/brokre-aarch64-apple-darwin.tar.gz"
    sha256 "2c667f8921fb70d7fb122119c1248d56a8c7b56c8973e42b101f02d05f1f3859"
  elsif OS.linux? && Hardware::CPU.intel?
    url "https://github.com/Furowu/brokre/releases/download/v0.1.6/brokre-x86_64-unknown-linux-gnu.tar.gz"
    sha256 "7c5e5b86102899f7543de6cea66d97e3f773201d23083bced969b942be529188"
  elsif OS.linux? && Hardware::CPU.arm?
    url "https://github.com/Furowu/brokre/releases/download/v0.1.6/brokre-aarch64-unknown-linux-gnu.tar.gz"
    sha256 "7c9bd306a0656deb16728323f195278ac776459a0b56419c5c56deef85cce0f2"
  end

  def install
    bin.install "brokre"
  end

  test do
    system "#{bin}/brokre", "--version"
  end
end

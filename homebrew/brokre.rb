class Brokre < Formula
  desc "AI-safe credential broker CLI"
  homepage "https://github.com/Furowu/brokre"
  version "0.2.36"

  if OS.mac? && Hardware::CPU.intel?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.36/brokre-x86_64-apple-darwin.tar.gz"
    sha256 "2ee42f06cb477f00980b864871220c352635069701767aa78e4d637b47eabc1b"
  elsif OS.mac? && Hardware::CPU.arm?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.36/brokre-aarch64-apple-darwin.tar.gz"
    sha256 "2fb3e5d1323635a7e803a00100c15f2bf4d5d53c1fbf68b3cb7c2b67fde0c88c"
  elsif OS.linux? && Hardware::CPU.intel?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.36/brokre-x86_64-unknown-linux-gnu.tar.gz"
    sha256 "2788faa9d13b8f12d2db3949fece2b4aaa605f98e7309b29c38c2579130731b7"
  elsif OS.linux? && Hardware::CPU.arm?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.36/brokre-aarch64-unknown-linux-gnu.tar.gz"
    sha256 "879774756047481422b8515b166cde4c5e213fb522702f14c1154f8d4c16c093"
  end

  def install
    bin.install "brokre"
  end

  test do
    system "#{bin}/brokre", "--version"
  end
end

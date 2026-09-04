class Brokre < Formula
  desc "AI-safe credential broker CLI"
  homepage "https://github.com/Furowu/brokre"
  version "0.2.25"

  if OS.mac? && Hardware::CPU.intel?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.25/brokre-x86_64-apple-darwin.tar.gz"
    sha256 "b3bd4069f337fcd2a10151d92b6cc73dc00cc2a2dd6c31e711f339095c94f6b3"
  elsif OS.mac? && Hardware::CPU.arm?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.25/brokre-aarch64-apple-darwin.tar.gz"
    sha256 "1e6e3c4d57a2c53d6e1067ffcfd8946de8cbdc4b114c821b57660e6936b588d1"
  elsif OS.linux? && Hardware::CPU.intel?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.25/brokre-x86_64-unknown-linux-gnu.tar.gz"
    sha256 "c1abf049afa6a088535546cab1892f3829e0f8acb1cc8070fd8222518415ac6b"
  elsif OS.linux? && Hardware::CPU.arm?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.25/brokre-aarch64-unknown-linux-gnu.tar.gz"
    sha256 "8c8b46299be5123b0cd180c03123520a5d2e00d570bd9fb7f914bad5711ddefe"
  end

  def install
    bin.install "brokre"
  end

  test do
    system "#{bin}/brokre", "--version"
  end
end

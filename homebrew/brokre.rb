class Brokre < Formula
  desc "AI-safe credential broker CLI"
  homepage "https://github.com/Furowu/brokre"
  version "0.2.23"

  if OS.mac? && Hardware::CPU.intel?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.23/brokre-x86_64-apple-darwin.tar.gz"
    sha256 "6d1d25466fa654a3bfd2c33d1605c36b2f29010d6a244d11f5fefb4e03adf52e"
  elsif OS.mac? && Hardware::CPU.arm?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.23/brokre-aarch64-apple-darwin.tar.gz"
    sha256 "ddb4173b6f1dcabc36c353b0ea07a9c75cab65c4093236078c1986f7e08bbc36"
  elsif OS.linux? && Hardware::CPU.intel?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.23/brokre-x86_64-unknown-linux-gnu.tar.gz"
    sha256 "cf87db83a8e0f9bfe28eaf33efc8ca9f2a88c709c0a9eeb2ad0d8ff3109ad4df"
  elsif OS.linux? && Hardware::CPU.arm?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.23/brokre-aarch64-unknown-linux-gnu.tar.gz"
    sha256 "2d5d4e1d1e75cb265a45b21c5481f16626f22150f8c3433189441bd135b4aba4"
  end

  def install
    bin.install "brokre"
  end

  test do
    system "#{bin}/brokre", "--version"
  end
end

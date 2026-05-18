class Brokr < Formula
  desc "AI-safe credential broker CLI"
  homepage "https://github.com/brokr/brokr"
  version "0.1.0"

  if OS.mac? && Hardware::CPU.intel?
    url "https://github.com/brokr/brokr/releases/download/v0.1.0/brokr-x86_64-apple-darwin.tar.gz"
    sha256 "PLACEHOLDER"
  elsif OS.mac? && Hardware::CPU.arm?
    url "https://github.com/brokr/brokr/releases/download/v0.1.0/brokr-aarch64-apple-darwin.tar.gz"
    sha256 "PLACEHOLDER"
  elsif OS.linux? && Hardware::CPU.intel?
    url "https://github.com/brokr/brokr/releases/download/v0.1.0/brokr-x86_64-unknown-linux-gnu.tar.gz"
    sha256 "PLACEHOLDER"
  elsif OS.linux? && Hardware::CPU.arm?
    url "https://github.com/brokr/brokr/releases/download/v0.1.0/brokr-aarch64-unknown-linux-gnu.tar.gz"
    sha256 "PLACEHOLDER"
  end

  def install
    bin.install "brokr"
  end

  test do
    system "#{bin}/brokr", "--version"
  end
end

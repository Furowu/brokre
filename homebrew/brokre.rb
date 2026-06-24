class Brokre < Formula
  desc "AI-safe credential broker CLI"
  homepage "https://github.com/Furowu/brokre"
  version "0.2.15"

  if OS.mac? && Hardware::CPU.intel?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.15/brokre-x86_64-apple-darwin.tar.gz"
    sha256 "7bf48dbb3b66e0a164e1327010e71e431186989d2529d29e2fd3090455fa2590"
  elsif OS.mac? && Hardware::CPU.arm?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.15/brokre-aarch64-apple-darwin.tar.gz"
    sha256 "04df583ef15180e24171851392f025b52656df20258d40fe1d0af95ad663e413"
  elsif OS.linux? && Hardware::CPU.intel?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.15/brokre-x86_64-unknown-linux-gnu.tar.gz"
    sha256 "b0a545ec834a3509a99ce8709799cde2054e4ad0c8947b71bbbaa11aa0d70192"
  elsif OS.linux? && Hardware::CPU.arm?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.15/brokre-aarch64-unknown-linux-gnu.tar.gz"
    sha256 "f6be5d31554e874fd243c1052da6541a41675e5f33855addb14f371d9bb47557"
  end

  def install
    bin.install "brokre"
  end

  test do
    system "#{bin}/brokre", "--version"
  end
end

class Brokre < Formula
  desc "AI-safe credential broker CLI"
  homepage "https://github.com/Furowu/brokre"
  version "0.2.22"

  if OS.mac? && Hardware::CPU.intel?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.22/brokre-x86_64-apple-darwin.tar.gz"
    sha256 "5c60d24d82ec61a39c6416c00430464e1570e57169ef6f0cbc1d24ba5a57bef1"
  elsif OS.mac? && Hardware::CPU.arm?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.22/brokre-aarch64-apple-darwin.tar.gz"
    sha256 "524b396d7570737872a9e997e8a2e2f1ff2caf524d0b22322552c16f5762059c"
  elsif OS.linux? && Hardware::CPU.intel?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.22/brokre-x86_64-unknown-linux-gnu.tar.gz"
    sha256 "5831024f229eb7547972e750a2c8e48fcd2ebcb9e771c1488b500ce82b1853f1"
  elsif OS.linux? && Hardware::CPU.arm?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.22/brokre-aarch64-unknown-linux-gnu.tar.gz"
    sha256 "06eb220cf65b73b81f7c5764a44773c14005276ee76019f601b203d497d8e279"
  end

  def install
    bin.install "brokre"
  end

  test do
    system "#{bin}/brokre", "--version"
  end
end

class Brokre < Formula
  desc "AI-safe credential broker CLI"
  homepage "https://github.com/Furowu/brokre"
  version "0.2.17"

  if OS.mac? && Hardware::CPU.intel?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.17/brokre-x86_64-apple-darwin.tar.gz"
    sha256 "5190bf6c97873a2e054d2245e2a04ef067a12d40fc1e8d55dbbb3944af3b2b67"
  elsif OS.mac? && Hardware::CPU.arm?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.17/brokre-aarch64-apple-darwin.tar.gz"
    sha256 "0c6f44c1048e7148aacd05fad56ac19aa2bbe2266f139a407406b70c554ad299"
  elsif OS.linux? && Hardware::CPU.intel?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.17/brokre-x86_64-unknown-linux-gnu.tar.gz"
    sha256 "8c4afffbfd7208f9867a9d029cb22801550a9d6b7f810f181b578c3a3fb5f65a"
  elsif OS.linux? && Hardware::CPU.arm?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.17/brokre-aarch64-unknown-linux-gnu.tar.gz"
    sha256 "72fe4811fce121e7926cb1def5e12a82c7194dd5b0680ce65c4e97202817776f"
  end

  def install
    bin.install "brokre"
  end

  test do
    system "#{bin}/brokre", "--version"
  end
end

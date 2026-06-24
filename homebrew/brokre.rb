class Brokre < Formula
  desc "AI-safe credential broker CLI"
  homepage "https://github.com/Furowu/brokre"
  version "0.2.12"

  if OS.mac? && Hardware::CPU.intel?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.12/brokre-x86_64-apple-darwin.tar.gz"
    sha256 "ab93dbb0d0e0b3ee16047ba8ebd72298807d5826be676fc7173cd138dbabc65b"
  elsif OS.mac? && Hardware::CPU.arm?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.12/brokre-aarch64-apple-darwin.tar.gz"
    sha256 "cdf28e59c32973605430b68b2aeddf4d1462cce80933795699e43301d15bd36b"
  elsif OS.linux? && Hardware::CPU.intel?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.12/brokre-x86_64-unknown-linux-gnu.tar.gz"
    sha256 "1187b24c6193380f6e20fbefa4e24f5793386169f66ac9aff612e98353c139c5"
  elsif OS.linux? && Hardware::CPU.arm?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.12/brokre-aarch64-unknown-linux-gnu.tar.gz"
    sha256 "e5d5d777db2417b20d1b6d8799cc8fc023517aabe7110159aa5520d8bb5ef7f4"
  end

  def install
    bin.install "brokre"
  end

  test do
    system "#{bin}/brokre", "--version"
  end
end

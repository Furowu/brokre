class Brokre < Formula
  desc "AI-safe credential broker CLI"
  homepage "https://github.com/Furowu/brokre"
  version "0.2.23"

  if OS.mac? && Hardware::CPU.intel?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.23/brokre-x86_64-apple-darwin.tar.gz"
    sha256 "ef7eef66a8b562aab43217df4c3266dca0644679c9d5830074c8e91bc3c6a260"
  elsif OS.mac? && Hardware::CPU.arm?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.23/brokre-aarch64-apple-darwin.tar.gz"
    sha256 "24e14b7baba05a01e87403891dd75308950cf6008bea74959f72af6a461b995e"
  elsif OS.linux? && Hardware::CPU.intel?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.23/brokre-x86_64-unknown-linux-gnu.tar.gz"
    sha256 "1411c6135b65b74db11615c7069b1405060302ef583fed8726439c569ded1b20"
  elsif OS.linux? && Hardware::CPU.arm?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.23/brokre-aarch64-unknown-linux-gnu.tar.gz"
    sha256 "a0b4913a3db02187bd861f0e168ddf8ff033fcf2dff331ba310b16add76b2a4a"
  end

  def install
    bin.install "brokre"
  end

  test do
    system "#{bin}/brokre", "--version"
  end
end

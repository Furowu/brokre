class Brokre < Formula
  desc "AI-safe credential broker CLI"
  homepage "https://github.com/Furowu/brokre"
  version "0.2.29"

  if OS.mac? && Hardware::CPU.intel?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.29/brokre-x86_64-apple-darwin.tar.gz"
    sha256 "d460df93f4e17cb0193831be9695d1da52ae4bb5f95f4e6a4fe49ea78a4cba9a"
  elsif OS.mac? && Hardware::CPU.arm?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.29/brokre-aarch64-apple-darwin.tar.gz"
    sha256 "74633867cfc925d86d8e62758bbbe1bf1fd81f30b07169e9e30cb314eaa9726b"
  elsif OS.linux? && Hardware::CPU.intel?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.29/brokre-x86_64-unknown-linux-gnu.tar.gz"
    sha256 "7cadc7938c284aa959abd19c05f747a0c99f731fd65333fa6802521795aa3b58"
  elsif OS.linux? && Hardware::CPU.arm?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.29/brokre-aarch64-unknown-linux-gnu.tar.gz"
    sha256 "07c413f56ddd47daf60e185663cb11a2db7104646f7731ba04a4ba3c430f42f1"
  end

  def install
    bin.install "brokre"
  end

  test do
    system "#{bin}/brokre", "--version"
  end
end

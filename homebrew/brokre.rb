class Brokre < Formula
  desc "AI-safe credential broker CLI"
  homepage "https://github.com/Furowu/brokre"
  version "0.1.19"

  if OS.mac? && Hardware::CPU.intel?
    url "https://github.com/Furowu/brokre/releases/download/v0.1.19/brokre-x86_64-apple-darwin.tar.gz"
    sha256 "cb2655cc711656fbb531f042347d89116ed8dd1c47da6117f8b0a2056d404fe9"
  elsif OS.mac? && Hardware::CPU.arm?
    url "https://github.com/Furowu/brokre/releases/download/v0.1.19/brokre-aarch64-apple-darwin.tar.gz"
    sha256 "ff89ccacd3888303549f97486defbc451b7b7216d9fdd084c81661f8c4230bc7"
  elsif OS.linux? && Hardware::CPU.intel?
    url "https://github.com/Furowu/brokre/releases/download/v0.1.19/brokre-x86_64-unknown-linux-gnu.tar.gz"
    sha256 "26d2b5e288c37f62808365ebf62d3295668865a7ed7951e2b398e98640da43cb"
  elsif OS.linux? && Hardware::CPU.arm?
    url "https://github.com/Furowu/brokre/releases/download/v0.1.19/brokre-aarch64-unknown-linux-gnu.tar.gz"
    sha256 "cf78ef107f7d283478a6caafd09a73ec8d548d16030ecbe3fbc8c52950751c69"
  end

  def install
    bin.install "brokre"
  end

  test do
    system "#{bin}/brokre", "--version"
  end
end

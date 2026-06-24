class Brokre < Formula
  desc "AI-safe credential broker CLI"
  homepage "https://github.com/Furowu/brokre"
  version "0.2.13"

  if OS.mac? && Hardware::CPU.intel?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.13/brokre-x86_64-apple-darwin.tar.gz"
    sha256 "64a963bec4a7d51f8b85ec84c9f24cccfd9f7fa931ec30056a1d64c3417e10d5"
  elsif OS.mac? && Hardware::CPU.arm?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.13/brokre-aarch64-apple-darwin.tar.gz"
    sha256 "d3a981e7753487a598b32e522eb7bffe3a06625f1598dd3422607f71c0d20786"
  elsif OS.linux? && Hardware::CPU.intel?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.13/brokre-x86_64-unknown-linux-gnu.tar.gz"
    sha256 "5c963584f2cb55fc9dca065d352e92ca0b63719ae09d6705b305ff6c4d489173"
  elsif OS.linux? && Hardware::CPU.arm?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.13/brokre-aarch64-unknown-linux-gnu.tar.gz"
    sha256 "967de7c631cb0cf783835a482a7b074ee9d163f465f31ca673f5ab5c362fab2b"
  end

  def install
    bin.install "brokre"
  end

  test do
    system "#{bin}/brokre", "--version"
  end
end

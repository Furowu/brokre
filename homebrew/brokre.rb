class Brokre < Formula
  desc "AI-safe credential broker CLI"
  homepage "https://github.com/Furowu/brokre"
  version "0.1.36"

  if OS.mac? && Hardware::CPU.intel?
    url "https://github.com/Furowu/brokre/releases/download/v0.1.36/brokre-x86_64-apple-darwin.tar.gz"
    sha256 "a7e70923851562dc44d925c2430836be23886d666cb4830e13a2b37a594d7dc3"
  elsif OS.mac? && Hardware::CPU.arm?
    url "https://github.com/Furowu/brokre/releases/download/v0.1.36/brokre-aarch64-apple-darwin.tar.gz"
    sha256 "902495de9617a68a29ffa0090c56668118c861d813cc4ffcb2dc39463491c439"
  elsif OS.linux? && Hardware::CPU.intel?
    url "https://github.com/Furowu/brokre/releases/download/v0.1.36/brokre-x86_64-unknown-linux-gnu.tar.gz"
    sha256 "a4b4c57d577e5b72a780a9faf6adba9eb9135cbe2f2aa7d33e396defcc5831d9"
  elsif OS.linux? && Hardware::CPU.arm?
    url "https://github.com/Furowu/brokre/releases/download/v0.1.36/brokre-aarch64-unknown-linux-gnu.tar.gz"
    sha256 "f7808924f35ac4b5d25b4e80c87c6a4815a2443855665fcc6b6b590a35c3deee"
  end

  def install
    bin.install "brokre"
  end

  test do
    system "#{bin}/brokre", "--version"
  end
end

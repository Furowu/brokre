class Brokre < Formula
  desc "AI-safe credential broker CLI"
  homepage "https://github.com/Furowu/brokre"
  version "0.1.20"

  if OS.mac? && Hardware::CPU.intel?
    url "https://github.com/Furowu/brokre/releases/download/v0.1.20/brokre-x86_64-apple-darwin.tar.gz"
    sha256 "61c848de7c4f55eddb87d7813a0ed0d0158d576a4bc2a015ffec600eb07bfe12"
  elsif OS.mac? && Hardware::CPU.arm?
    url "https://github.com/Furowu/brokre/releases/download/v0.1.20/brokre-aarch64-apple-darwin.tar.gz"
    sha256 "974d364a476502de5352d7b80ddd9e636147344ffab345816d04df48da8ed9db"
  elsif OS.linux? && Hardware::CPU.intel?
    url "https://github.com/Furowu/brokre/releases/download/v0.1.20/brokre-x86_64-unknown-linux-gnu.tar.gz"
    sha256 "bc5952041b27dd6d85845d7e86a7cc8da6aefc14c6b25ec3a7a018680f975386"
  elsif OS.linux? && Hardware::CPU.arm?
    url "https://github.com/Furowu/brokre/releases/download/v0.1.20/brokre-aarch64-unknown-linux-gnu.tar.gz"
    sha256 "1b1c1c5cf4e812efdc508f624bccde42ea3f438abcac17b291f847a809892b11"
  end

  def install
    bin.install "brokre"
  end

  test do
    system "#{bin}/brokre", "--version"
  end
end

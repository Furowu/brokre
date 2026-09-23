class Brokre < Formula
  desc "AI-safe credential broker CLI"
  homepage "https://github.com/Furowu/brokre"
  version "0.2.34"

  if OS.mac? && Hardware::CPU.intel?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.34/brokre-x86_64-apple-darwin.tar.gz"
    sha256 "47e9b3da4aa827ce8f3a41ba75e1575e08b466148e78caa8cb225fba1f21d673"
  elsif OS.mac? && Hardware::CPU.arm?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.34/brokre-aarch64-apple-darwin.tar.gz"
    sha256 "643d4b176b0bb2c1711b7a64534fb2677bfe72eb23b8bb99a37ef6baa0f00e1f"
  elsif OS.linux? && Hardware::CPU.intel?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.34/brokre-x86_64-unknown-linux-gnu.tar.gz"
    sha256 "d315d2c6bea4d469a0d126701699cde7ce4cd001282f50e5217be1f0ef3dffbb"
  elsif OS.linux? && Hardware::CPU.arm?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.34/brokre-aarch64-unknown-linux-gnu.tar.gz"
    sha256 "ff25ed1b03ec0c36c083595035aeaa55f81d3ee99506f0ce880172f3774f7a82"
  end

  def install
    bin.install "brokre"
  end

  test do
    system "#{bin}/brokre", "--version"
  end
end

class Brokre < Formula
  desc "AI-safe credential broker CLI"
  homepage "https://github.com/Furowu/brokre"
  version "0.2.32"

  if OS.mac? && Hardware::CPU.intel?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.32/brokre-x86_64-apple-darwin.tar.gz"
    sha256 "080ce0d619235bd207eee5929b3c8577ad3d1f6b63700af604f6ed77816cfa5b"
  elsif OS.mac? && Hardware::CPU.arm?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.32/brokre-aarch64-apple-darwin.tar.gz"
    sha256 "e748d2f2c354fbbe3e5c63e9c6c31e16d123835265d163528f28b2cfb4a1ed33"
  elsif OS.linux? && Hardware::CPU.intel?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.32/brokre-x86_64-unknown-linux-gnu.tar.gz"
    sha256 "9dd3b1e9d5df67b0c9ca0f0615816f266ebef7047caa27c66ac8891b3b98019f"
  elsif OS.linux? && Hardware::CPU.arm?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.32/brokre-aarch64-unknown-linux-gnu.tar.gz"
    sha256 "3d2bfbd8d72733ef4011534c26e60babf5db58632672b7973fdfdadcfdec6ee5"
  end

  def install
    bin.install "brokre"
  end

  test do
    system "#{bin}/brokre", "--version"
  end
end

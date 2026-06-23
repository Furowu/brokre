class Brokre < Formula
  desc "AI-safe credential broker CLI"
  homepage "https://github.com/Furowu/brokre"
  version "0.2.6"

  if OS.mac? && Hardware::CPU.intel?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.6/brokre-x86_64-apple-darwin.tar.gz"
    sha256 "13c84feb542db11d399d9d147a91fdafb20b09d2477adcdb8b3d729bef6a7ce2"
  elsif OS.mac? && Hardware::CPU.arm?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.6/brokre-aarch64-apple-darwin.tar.gz"
    sha256 "cda70025b0f6a8b9b760f4c47b08a4ecb967de77adb1bf0ba8380bc68e42b8bd"
  elsif OS.linux? && Hardware::CPU.intel?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.6/brokre-x86_64-unknown-linux-gnu.tar.gz"
    sha256 "4f79dde67288a4d62dedfee5342d68681b98907f9e30c5aa7091020ec0f62d59"
  elsif OS.linux? && Hardware::CPU.arm?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.6/brokre-aarch64-unknown-linux-gnu.tar.gz"
    sha256 "71f81e69e49e46e35e9ea370266b0f56a8652d19ce018191c450b3ac2478a08e"
  end

  def install
    bin.install "brokre"
  end

  test do
    system "#{bin}/brokre", "--version"
  end
end

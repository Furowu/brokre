class Brokre < Formula
  desc "AI-safe credential broker CLI"
  homepage "https://github.com/Furowu/brokre"
  version "0.2.32"

  if OS.mac? && Hardware::CPU.intel?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.32/brokre-x86_64-apple-darwin.tar.gz"
    sha256 "a5f6bbebb5024384944b105497518721ec4d8eb01d8480a7e0ea1f988026b989"
  elsif OS.mac? && Hardware::CPU.arm?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.32/brokre-aarch64-apple-darwin.tar.gz"
    sha256 "d1618ce818e35c16cf6b58183727ca1e76344138fa9e7a9d215fadcd21e160d4"
  elsif OS.linux? && Hardware::CPU.intel?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.32/brokre-x86_64-unknown-linux-gnu.tar.gz"
    sha256 "0e11119307da05dd5cbf3633fbad3ac53145d5bef08bff73bf7795fb82f3a2d5"
  elsif OS.linux? && Hardware::CPU.arm?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.32/brokre-aarch64-unknown-linux-gnu.tar.gz"
    sha256 "1446fe98e7eb4c542513d4df50e680af7456311ac2443c6e887a307cb6ff2605"
  end

  def install
    bin.install "brokre"
  end

  test do
    system "#{bin}/brokre", "--version"
  end
end

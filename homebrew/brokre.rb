class Brokre < Formula
  desc "AI-safe credential broker CLI"
  homepage "https://github.com/Furowu/brokre"
  version "0.2.1"

  if OS.mac? && Hardware::CPU.intel?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.1/brokre-x86_64-apple-darwin.tar.gz"
    sha256 "a6690d76d6f7801ec4a13e18ffc27f6cd2be698161eb72aeb7f53b7c94c1faca"
  elsif OS.mac? && Hardware::CPU.arm?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.1/brokre-aarch64-apple-darwin.tar.gz"
    sha256 "d337f12adff6f366b26f5cbb4bf717c5c1af92b2d3e7136936cd7e636edbd85d"
  elsif OS.linux? && Hardware::CPU.intel?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.1/brokre-x86_64-unknown-linux-gnu.tar.gz"
    sha256 "c66c8ddc3510a410c0a26760a075358d32489a6362f32ecc75bf5f961453cf11"
  elsif OS.linux? && Hardware::CPU.arm?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.1/brokre-aarch64-unknown-linux-gnu.tar.gz"
    sha256 "35234a423bd103e3eb977b43ee87065143737e6bff79b2957d4af45308611eca"
  end

  def install
    bin.install "brokre"
  end

  test do
    system "#{bin}/brokre", "--version"
  end
end

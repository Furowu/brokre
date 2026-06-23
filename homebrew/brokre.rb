class Brokre < Formula
  desc "AI-safe credential broker CLI"
  homepage "https://github.com/Furowu/brokre"
  version "0.2.8"

  if OS.mac? && Hardware::CPU.intel?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.8/brokre-x86_64-apple-darwin.tar.gz"
    sha256 "429d6e20fe7e9c11c490cd67bb888f67282b23e57e88711fab599691199dd6b0"
  elsif OS.mac? && Hardware::CPU.arm?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.8/brokre-aarch64-apple-darwin.tar.gz"
    sha256 "9e343821c8dfbc8135c1e67ecc3edd2cc506008228e8d3cb3bde47b54e2f56c9"
  elsif OS.linux? && Hardware::CPU.intel?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.8/brokre-x86_64-unknown-linux-gnu.tar.gz"
    sha256 "a0b8690137de3de5aafc75a7a768c06d1683dadd83f72c16c32dbb98429d8dc6"
  elsif OS.linux? && Hardware::CPU.arm?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.8/brokre-aarch64-unknown-linux-gnu.tar.gz"
    sha256 "08544382c5e7941c2d45df9c507a6a935fa7dfb361d6731688d485221fbf51bd"
  end

  def install
    bin.install "brokre"
  end

  test do
    system "#{bin}/brokre", "--version"
  end
end

class Brokre < Formula
  desc "AI-safe credential broker CLI"
  homepage "https://github.com/Furowu/brokre"
  version "0.2.3"

  if OS.mac? && Hardware::CPU.intel?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.3/brokre-x86_64-apple-darwin.tar.gz"
    sha256 "c7edf32af4a7b099d8d35ede4ea46bdf516cee3ad5df7a5dadae7a155e0ceb62"
  elsif OS.mac? && Hardware::CPU.arm?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.3/brokre-aarch64-apple-darwin.tar.gz"
    sha256 "2f7857d19e713bc899ef3061da839d07fa6d979e13369744065ca25f2770e70a"
  elsif OS.linux? && Hardware::CPU.intel?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.3/brokre-x86_64-unknown-linux-gnu.tar.gz"
    sha256 "a04368c788e39c1ca017be06197de899b40f5fda296b83f88e5bd5546b1d1916"
  elsif OS.linux? && Hardware::CPU.arm?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.3/brokre-aarch64-unknown-linux-gnu.tar.gz"
    sha256 "79b8e58249f9263ab8071605ceb2fbc08555fecfc4a6e48580903991346d57c4"
  end

  def install
    bin.install "brokre"
  end

  test do
    system "#{bin}/brokre", "--version"
  end
end

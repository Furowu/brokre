class Brokre < Formula
  desc "AI-safe credential broker CLI"
  homepage "https://github.com/Furowu/brokre"
  version "0.1.18"

  if OS.mac? && Hardware::CPU.intel?
    url "https://github.com/Furowu/brokre/releases/download/v0.1.18/brokre-x86_64-apple-darwin.tar.gz"
    sha256 "a910d7ba900278f1760c0665573b12e9c0b559238c6814c944a9d6529f63cc5a"
  elsif OS.mac? && Hardware::CPU.arm?
    url "https://github.com/Furowu/brokre/releases/download/v0.1.18/brokre-aarch64-apple-darwin.tar.gz"
    sha256 "7b3003c4de451e021ffc966dedf3594ca05cc5140ee44e37a918abb93709d3e9"
  elsif OS.linux? && Hardware::CPU.intel?
    url "https://github.com/Furowu/brokre/releases/download/v0.1.18/brokre-x86_64-unknown-linux-gnu.tar.gz"
    sha256 "8107c547bfb17d5191f302b0c19011cd5d54d9f07a7ab62983fde0c4826ad900"
  elsif OS.linux? && Hardware::CPU.arm?
    url "https://github.com/Furowu/brokre/releases/download/v0.1.18/brokre-aarch64-unknown-linux-gnu.tar.gz"
    sha256 "3852ad00355cec502d4220e9cc80a4d1f5d83af3a2a868c6d9473b4deec0b996"
  end

  def install
    bin.install "brokre"
  end

  test do
    system "#{bin}/brokre", "--version"
  end
end

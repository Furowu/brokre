class Brokre < Formula
  desc "AI-safe credential broker CLI"
  homepage "https://github.com/Furowu/brokre"
  version "0.2.9"

  if OS.mac? && Hardware::CPU.intel?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.9/brokre-x86_64-apple-darwin.tar.gz"
    sha256 "8d5e3f07abb7e0702bf4fad940a80fb6b01d3f5a4a9366f8c07ce5b8074cd0d4"
  elsif OS.mac? && Hardware::CPU.arm?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.9/brokre-aarch64-apple-darwin.tar.gz"
    sha256 "99c33a5e6b71b8e95572d4a4e955c3d9442ca3e042738dcfc05267d496f56fe0"
  elsif OS.linux? && Hardware::CPU.intel?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.9/brokre-x86_64-unknown-linux-gnu.tar.gz"
    sha256 "245d0a2cd5fe9889c56f88a3f3b2b02b09836cea68c680fa69b9f0f934120eac"
  elsif OS.linux? && Hardware::CPU.arm?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.9/brokre-aarch64-unknown-linux-gnu.tar.gz"
    sha256 "6ad0eed39b8f6cffeab9a7c2d01ce51e28acb40c13a2640d4275a50a8dd1c6d5"
  end

  def install
    bin.install "brokre"
  end

  test do
    system "#{bin}/brokre", "--version"
  end
end

class Brokre < Formula
  desc "AI-safe credential broker CLI"
  homepage "https://github.com/Furowu/brokre"
  version "0.1.34"

  if OS.mac? && Hardware::CPU.intel?
    url "https://github.com/Furowu/brokre/releases/download/v0.1.34/brokre-x86_64-apple-darwin.tar.gz"
    sha256 "fcb63a4db631d2cb531d04c6bb7d1c882b80fabbfab6cb8a83b947eea2ea13fd"
  elsif OS.mac? && Hardware::CPU.arm?
    url "https://github.com/Furowu/brokre/releases/download/v0.1.34/brokre-aarch64-apple-darwin.tar.gz"
    sha256 "adfe10e52fb9abeea9a8309bf17b4442b61a542d5b5860ff364035eb257e7385"
  elsif OS.linux? && Hardware::CPU.intel?
    url "https://github.com/Furowu/brokre/releases/download/v0.1.34/brokre-x86_64-unknown-linux-gnu.tar.gz"
    sha256 "c747f401f6fed4ae9e5953721a74973742ece7c3aa3d51dfaa20d2c52cf03048"
  elsif OS.linux? && Hardware::CPU.arm?
    url "https://github.com/Furowu/brokre/releases/download/v0.1.34/brokre-aarch64-unknown-linux-gnu.tar.gz"
    sha256 "20290f6248f1d1fa42c5a3356b3a5ee392cf56417635225f75b6c9a4bd8ff450"
  end

  def install
    bin.install "brokre"
  end

  test do
    system "#{bin}/brokre", "--version"
  end
end

class Brokre < Formula
  desc "AI-safe credential broker CLI"
  homepage "https://github.com/Furowu/brokre"
  version "0.1.22"

  if OS.mac? && Hardware::CPU.intel?
    url "https://github.com/Furowu/brokre/releases/download/v0.1.22/brokre-x86_64-apple-darwin.tar.gz"
    sha256 "00541f0413bf8403d0be47f71ee65ec21c3cc4ac06845507cda244da7e9ac8ab"
  elsif OS.mac? && Hardware::CPU.arm?
    url "https://github.com/Furowu/brokre/releases/download/v0.1.22/brokre-aarch64-apple-darwin.tar.gz"
    sha256 "8e0540ba5445127034e7933ccc3c35ace3a5a43785997936764bbe022b9c7aa3"
  elsif OS.linux? && Hardware::CPU.intel?
    url "https://github.com/Furowu/brokre/releases/download/v0.1.22/brokre-x86_64-unknown-linux-gnu.tar.gz"
    sha256 "ef6f2030dc9dde6c861527ba89d88a9e18b40407d94cd1700db321afca46bffc"
  elsif OS.linux? && Hardware::CPU.arm?
    url "https://github.com/Furowu/brokre/releases/download/v0.1.22/brokre-aarch64-unknown-linux-gnu.tar.gz"
    sha256 "e354e60b9458ea963be7169a5a9ef637ac3402e9370b9a54adc03d95dc75c647"
  end

  def install
    bin.install "brokre"
  end

  test do
    system "#{bin}/brokre", "--version"
  end
end

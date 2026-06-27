class Brokre < Formula
  desc "AI-safe credential broker CLI"
  homepage "https://github.com/Furowu/brokre"
  version "0.2.20"

  if OS.mac? && Hardware::CPU.intel?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.20/brokre-x86_64-apple-darwin.tar.gz"
    sha256 "21b3cc0431433863941d7037940212d05c5db570b26a2673c91d047d9187134b"
  elsif OS.mac? && Hardware::CPU.arm?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.20/brokre-aarch64-apple-darwin.tar.gz"
    sha256 "1edb401780a6b09b7c59627c2346341d496af0e66f61fd9e95dfb2aeaedebecb"
  elsif OS.linux? && Hardware::CPU.intel?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.20/brokre-x86_64-unknown-linux-gnu.tar.gz"
    sha256 "1a2e01235e1b9c46060eee3fe0bef4bfd6377fb8b96563ca48a72b10a38681da"
  elsif OS.linux? && Hardware::CPU.arm?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.20/brokre-aarch64-unknown-linux-gnu.tar.gz"
    sha256 "081d4add33be2648afcd5f1668e3ae9765846ea9b62e0cbc1fb2780ebb393976"
  end

  def install
    bin.install "brokre"
  end

  test do
    system "#{bin}/brokre", "--version"
  end
end

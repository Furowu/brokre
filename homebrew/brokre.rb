class Brokre < Formula
  desc "AI-safe credential broker CLI"
  homepage "https://github.com/Furowu/brokre"
  version "0.2.28"

  if OS.mac? && Hardware::CPU.intel?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.28/brokre-x86_64-apple-darwin.tar.gz"
    sha256 "c6ff5e7856296d9c613edf4dc410a19ca091177fdb08ff49259dcf7d1a5fe780"
  elsif OS.mac? && Hardware::CPU.arm?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.28/brokre-aarch64-apple-darwin.tar.gz"
    sha256 "51f63896de0ec6666005388afc0c91ee51b703bb2a7ceba844fec167b808069b"
  elsif OS.linux? && Hardware::CPU.intel?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.28/brokre-x86_64-unknown-linux-gnu.tar.gz"
    sha256 "dea98dd42ab7b30633110ab21162d4f816fbb877a9f0840c7522e09872f04730"
  elsif OS.linux? && Hardware::CPU.arm?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.28/brokre-aarch64-unknown-linux-gnu.tar.gz"
    sha256 "240aa2d41338ff360f3ef42133b03dfa97c243091ee279f4a6108dd6ab0b69c4"
  end

  def install
    bin.install "brokre"
  end

  test do
    system "#{bin}/brokre", "--version"
  end
end

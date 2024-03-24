#!/bin/bash

# build and bundle the nerum binary and license files into a zip file
# usage: 
# chmod +x ./scripts/bundle_mac.sh　(Only needed if not already set)
# ./scripts/bundle_mac.sh

bin_name="nerum"
version="1.1.0"
os_arch="x86_64-apple-darwin"
dist_dir="./dist"

zip_filename="nerum-$version-$os_arch.zip"

echo "Building nerum binary for $os_arch"
cargo build --release

# if dist_dir does not exist, create it
if [ ! -d $dist_dir ]; then
    mkdir $dist_dir
fi

cp ./target/release/$bin_name $dist_dir/$bin_name
cp ./LICENSE $dist_dir/LICENSE

cd $dist_dir
echo "Creating zip file $zip_filename"
zip -r $zip_filename $bin_name LICENSE
echo "Done"
